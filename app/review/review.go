package review

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/bmatcuk/doublestar/v4"
	config2 "github.com/jc-lab/shim-review-bot/app/config"
	"github.com/jc-lab/shim-review-bot/app/download"
	"github.com/jc-lab/shim-review-bot/app/review/testcase"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type outputState int

const (
	stateNormal    outputState = iota
	stateSha256sum outputState = iota
)

type HashSum struct {
	Hash string
	Path string
}

type FileAndHash struct {
	Path        string
	Name        string
	RelatedPath string
	Hash        string
}

type PatchFile struct {
	Path        string
	Name        string
	RelatedPath string
}

type SbatItem struct {
	Vendor  string
	Version int
}

type EfiFile struct {
	FileAndHash
	ComputedHash       string
	Sbat               string
	SbatLevel          []*SbatItem
	VendorCert         []byte
	VendorDeAuthorized []byte
	FlagNXCompat       bool
	TestResults        []*testcase.TestResult
}

type WorkingContext struct {
	sourceUrl string
	source    *download.Source

	vendorCertPath    string
	vendorCertContent []byte
	sbatPath          string
	sbatContent       string

	prebuiltEfiFileHashes map[string]*FileAndHash
	patchFiles            []*PatchFile

	outputState   outputState
	hashes        []*HashSum
	exportedFiles map[string]*FileAndHash

	efiFiles []*EfiFile

	sbatLevel string

	buildErr error
	otherErr error
}

var (
	shimEfiPathPattern = regexp.MustCompile("/shim[^.]+\\.efi$")
)

func Main(flagSet *flag.FlagSet, args []string) {
	var configFile string
	var sourceRoot string
	var buildCommand string
	var outputFile string
	var reportFile string
	var buildLogFile string

	var workingContext WorkingContext

	flagSet.StringVar(&configFile, "config", "", "config file")
	flagSet.StringVar(&sourceRoot, "source-root", "", "sourceUrl root to find shim.efi")
	flagSet.StringVar(&workingContext.sourceUrl, "source", "", "source url")

	flagSet.StringVar(&buildCommand, "build-script", "", "build-script file")
	flagSet.StringVar(&outputFile, "output-file", "", "docker output file (tar)")
	flagSet.StringVar(&workingContext.vendorCertPath, "vendor-cert", "vendor_cert.der", "vendor cert der file")
	flagSet.StringVar(&workingContext.sbatPath, "sbat", "sbat.csv", "vendor cert der file")
	flagSet.StringVar(&buildLogFile, "build-log", "", "build log output file")

	flagSet.StringVar(&reportFile, "report-output", "", "report output file")
	flagSet.Parse(args)

	var sbatRaw []byte
	var tempDir string

	if configFile != "" {
		raw, err := os.ReadFile(configFile)
		if err != nil {
			err = fmt.Errorf("config file read failed: %v", err)
			log.Println(err)
			workingContext.otherErr = err
			goto done
		}

		var config config2.Config
		if err = yaml.Unmarshal(raw, &config); err != nil {
			err = fmt.Errorf("config file parse failed: %v", err)
			log.Println(err)
			workingContext.otherErr = err
			goto done
		}

		if config.Source != "" {
			workingContext.sourceUrl = config.Source
		}
		if config.BuildScript != "" {
			buildCommand = config.BuildScript
		}
		if config.OutputFile != "" {
			outputFile = config.OutputFile
		}
		if config.VendorCert != "" {
			workingContext.vendorCertPath = config.VendorCert
		}
		if config.Sbat != "" {
			workingContext.sbatPath = config.Sbat
		}
	}

	if workingContext.sourceUrl != "" {
		workingContext.source = download.ParseSourceUrl(workingContext.sourceUrl)
	}

	workingContext.vendorCertContent, workingContext.otherErr = os.ReadFile(workingContext.vendorCertPath)
	if workingContext.otherErr != nil {
		log.Printf("vendor_cert open failed: %v", workingContext.otherErr)
		goto done
	}

	sbatRaw, workingContext.otherErr = os.ReadFile(workingContext.sbatPath)
	if workingContext.otherErr != nil {
		log.Printf("sbatContent.csv open failed: %v", workingContext.otherErr)
		goto done
	}
	workingContext.sbatContent = string(sbatRaw)

	workingContext.otherErr = workingContext.findPrebuiltEfiFiles(sourceRoot)
	if workingContext.otherErr != nil {
		log.Printf("cannot find prebuilt efi files: %v", workingContext.otherErr)
		goto done
	} else if len(workingContext.prebuiltEfiFileHashes) == 0 {
		err := fmt.Errorf("cannot find prebuilt efi files in %s", sourceRoot)
		workingContext.otherErr = err
		log.Println(err)
		goto done
	}

	workingContext.otherErr = workingContext.findPatches(sourceRoot)
	if workingContext.otherErr != nil {
		log.Printf("cannot find patch files: %v", workingContext.otherErr)
		goto done
	}

	workingContext.buildErr = workingContext.build(buildCommand, buildLogFile)
	if workingContext.buildErr != nil {
		log.Printf("build failed: %v", workingContext.buildErr)
		goto done
	}

	tempDir, workingContext.otherErr = os.MkdirTemp(os.TempDir(), "output-*")
	if workingContext.otherErr != nil {
		log.Printf("create temp failed: %v", workingContext.otherErr)
		goto done
	}

	workingContext.otherErr = workingContext.extractFiles(outputFile, tempDir)
	if workingContext.otherErr != nil {
		log.Printf("extractFiles failed: %v", workingContext.otherErr)
		goto done
	}

	for _, item := range workingContext.exportedFiles {
		basename := strings.ToLower(filepath.Base(item.Path))
		if !strings.HasSuffix(basename, ".efi") {
			continue
		}

		computedHash, err := hashFileSha256(item.Path)
		if err != nil {
			log.Printf("efi(%s) hash failed: %v", item.Path, err)
			continue
		}

		efiFile := &EfiFile{
			FileAndHash: FileAndHash{
				Path:        basename,
				Hash:        item.Hash,
				RelatedPath: item.RelatedPath,
			},
			ComputedHash: computedHash,
		}

		peFile, err := pe.Open(item.Path)
		if err != nil {
			log.Printf("efi(%s) open failed: %v", item.Path, err)
			continue
		}
		defer peFile.Close()

		section := peFile.Section(".sbat")
		if section != nil {
			raw, err := section.Data()
			if err != nil {
				log.Printf(".sbat read failed: %v", err)
			} else {
				raw = raw[:section.VirtualSize]
				efiFile.Sbat = string(raw)
			}
		}

		section = peFile.Section(".sbatlevel")
		if section != nil {
			raw, err := section.Data()
			if err != nil {
				log.Printf(".sbatlevel read failed: %v", err)
			} else {
				raw = raw[:section.VirtualSize]
				for _, chunk := range bytes.Split(raw[12:], []byte{0}) {
					if len(chunk) == 0 {
						break
					}
					workingContext.sbatLevel = string(chunk)
					efiFile.SbatLevel = parseSbat(string(chunk))
				}
			}
		}

		section = peFile.Section(".vendor_cert")
		if section != nil {
			raw, err := section.Data()
			if err != nil {
				log.Printf("vendor_cert read failed: %v", err)
			} else {
				raw = raw[:section.VirtualSize]

				vendorAuthorizedSize := binary.LittleEndian.Uint32(raw[0:4])
				vendorDeAuthorizedSize := binary.LittleEndian.Uint32(raw[4:8])
				vendorAuthorizedOffset := binary.LittleEndian.Uint32(raw[8:12])
				vendorDeAuthorizedOffset := binary.LittleEndian.Uint32(raw[12:16])

				vendorAuthorized := raw[vendorAuthorizedOffset : vendorAuthorizedOffset+vendorAuthorizedSize]
				efiFile.VendorCert = vendorAuthorized
				if vendorDeAuthorizedSize > 0 {
					vendorDeAuthorized := raw[vendorAuthorizedOffset : vendorDeAuthorizedOffset+vendorDeAuthorizedSize]
					efiFile.VendorDeAuthorized = vendorDeAuthorized
				}
			}
		}

		if optional, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
			efiFile.FlagNXCompat = optional.DllCharacteristics&0x100 != 0
		}
		if optional, ok := peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
			efiFile.FlagNXCompat = optional.DllCharacteristics&0x100 != 0
		}

		testContext := &testcase.TestContext{
			Pe: peFile,
		}
		efiFile.TestResults = testcase.DoTests(testContext)

		workingContext.efiFiles = append(workingContext.efiFiles, efiFile)
	}

done:
	if tempDir != "" {
		os.RemoveAll(tempDir)
	}

	report := workingContext.buildReport()
	println(report)

	if reportFile != "" {
		os.WriteFile(reportFile, []byte(report), 0644)
	}
}

var (
	linePattern    = regexp.MustCompile("^#[0-9]+ [^ ]+ (.+)$")
	hashSumPattern = regexp.MustCompile("([0-9a-f]+)\\s+(.+)")
)

func (w *WorkingContext) findPrebuiltEfiFiles(sourceRoot string) error {
	pattern := sourceRoot + "/**/shim*.efi"
	efiFiles, err := doublestar.FilepathGlob(pattern)
	if err != nil {
		return err
	}
	log.Printf("Search prebuilt shim efi files with '%s': %v", pattern, efiFiles)

	w.prebuiltEfiFileHashes = map[string]*FileAndHash{}

	for _, file := range efiFiles {
		hash, err := hashFileSha256(file)
		if err != nil {
			log.Printf("file(%s) hash failed: %v", file, err)
		} else {
			name := filepath.Base(file)
			rel, err := filepath.Rel(sourceRoot, file)
			if err != nil {
				log.Println("filepath.Rel failed: ", err)
			}
			w.prebuiltEfiFileHashes[name] = &FileAndHash{
				Path:        name,
				RelatedPath: rel,
				Hash:        hash,
			}
		}
	}

	return nil
}

func (w *WorkingContext) findPatches(sourceRoot string) error {
	pattern := sourceRoot + "/**/*.patch"
	patchFiles, err := doublestar.FilepathGlob(pattern)
	if err != nil {
		return err
	}
	log.Printf("Search patch files with '%s': %v", pattern, patchFiles)

	for _, file := range patchFiles {
		name := filepath.Base(file)
		rel, err := filepath.Rel(sourceRoot, file)
		if err != nil {
			log.Println("filepath.Rel failed: ", err)
		}
		w.patchFiles = append(w.patchFiles, &PatchFile{
			Name:        name,
			Path:        file,
			RelatedPath: rel,
		})
	}

	return nil
}

func (w *WorkingContext) build(buildCommand string, logFile string) error {
	cmd := exec.Command(buildCommand)
	cmd.Stdin = os.Stdin

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	var logFileStream io.WriteCloser
	if logFile != "" {
		logFileStream, err = os.OpenFile(logFile, os.O_RDWR|os.O_CREATE, 0644)
	}
	defer func() {
		if logFileStream != nil {
			logFileStream.Close()
		}
	}()

	go func() {
		dest := logFileStream
		if dest == nil {
			dest = os.Stderr
		}
		reader := io.TeeReader(stderr, dest)
		w.handleOutput(reader)
	}()
	go func() {
		dest := logFileStream
		if dest == nil {
			dest = os.Stdout
		}
		reader := io.TeeReader(stdout, dest)
		w.handleOutput(reader)
	}()

	err = cmd.Start()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		return err
	}

	return nil
}

func (w *WorkingContext) handleOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		matches := linePattern.FindStringSubmatch(line)
		if len(matches) > 0 {
			message := strings.Trim(matches[1], " \t")
			if strings.HasPrefix(message, "::review hash-start") {
				w.outputState = stateSha256sum
			} else if strings.HasPrefix(message, "::review hash-end") {
				w.outputState = stateNormal
			} else {
				switch w.outputState {
				case stateSha256sum:
					matches = hashSumPattern.FindStringSubmatch(message)
					if len(matches) > 0 {
						w.hashes = append(w.hashes, &HashSum{
							Hash: matches[1],
							Path: matches[2],
						})
					}
				}
			}
		}
	}
}

func (w *WorkingContext) extractFiles(tarFile string, outputDirectory string) error {
	w.exportedFiles = map[string]*FileAndHash{}

	file, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := tar.NewReader(file)

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		} else if header == nil {
			break
		}

		baseName := filepath.Base(header.Name)
		destFileName := filepath.Join(outputDirectory, baseName)

		if len(w.hashes) > 0 {
			// If there is a hash in the build log

			var hashEntry *HashSum
			for _, s := range w.hashes {
				if s.Path[1:] == header.Name {
					hashEntry = s
				}
			}

			if hashEntry != nil {
				f, err := os.OpenFile(destFileName, os.O_CREATE|os.O_RDWR, 0644)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err = io.Copy(f, reader); err != nil {
					return err
				}

				w.exportedFiles[baseName] = &FileAndHash{
					Path:        destFileName,
					Name:        baseName,
					RelatedPath: hashEntry.Path,
					Hash:        hashEntry.Hash,
				}
				continue
			}
		} else {
			// Find shim*.efi files by pattern.
			if shimEfiPathPattern.MatchString(header.Name) {
				log.Printf("found shim*.efi in '%s'", header.Name)
				f, err := os.OpenFile(destFileName, os.O_CREATE|os.O_RDWR, 0644)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err = io.Copy(f, reader); err != nil {
					return err
				}

				w.exportedFiles[baseName] = &FileAndHash{
					Path:        destFileName,
					Name:        filepath.Base(header.Name),
					RelatedPath: header.Name,
					Hash:        "",
				}
				continue
			}
		}

		if _, err = io.Copy(&DummyWriter{}, reader); err != nil {
			return err
		}
	}

	return nil
}

func (w *WorkingContext) buildPathToUrl(filepath string) string {
	return w.sourceUrl + "/" + filepath
}

func (w *WorkingContext) absPathToUrl(filepath string) string {
	if w.source == nil {
		return filepath
	}
	prefix := strings.TrimSuffix(strings.TrimSuffix(w.sourceUrl, "/"+w.source.Directory), "/")
	return prefix + "/" + filepath
}

func (w *WorkingContext) buildReport() string {
	var report = ""
	var success = true

	if w.buildErr != nil {
		success = false
		report += "## BUILD ERROR\n\n"
		report += "```\n"
		report += w.buildErr.Error()
		report += "\n```\n"
		goto done
	}
	if w.otherErr != nil {
		success = false
		report += "## REVIEW ERROR\n\n"
		report += "```\n"
		report += w.otherErr.Error()
		report += "\n```\n"
		goto done
	}

	if true {
		// ==================== VENDOR CERTIFICATE ====================
		report += "## Vendor Certificate\n\n"
		report += "Source: " + w.buildPathToUrl(w.vendorCertPath) + "\n"
		cert, err := x509.ParseCertificate(w.vendorCertContent)
		if err != nil {
			success = false
			report += "ERROR: " + err.Error() + "\n"
		} else {
			encoded := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: w.vendorCertContent,
			})
			report += "```\n" + string(encoded) + "\n```\n"
			report += "- Issuer : " + cert.Issuer.String() + "\n"
			report += "- Subject : " + cert.Subject.String() + "\n"
			report += "- NotAfter : " + cert.NotAfter.String() + "\n"
			if (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0 {
				report += "- [X] KeyUsage/DigitalSignature : OK\n"
			} else {
				success = false
				report += "- [ ] KeyUsage/DigitalSignature : **NO DigitalSignature in Key Usage!!!**\n"
			}
			hasExtKeyUsageCodeSigning := false
			for _, usage := range cert.ExtKeyUsage {
				if usage == x509.ExtKeyUsageCodeSigning {
					hasExtKeyUsageCodeSigning = true
				}
			}
			if hasExtKeyUsageCodeSigning {
				report += "- [X] ExtKeyUsage/CodeSigning : OK\n"
			} else {
				success = false
				report += "- [ ] ExtKeyUsage/CodeSigning : **NO CodeSigning in Ext Key Usage!!!**\n"
			}
		}
		report += "\n"

		// ==================== SBAT LEVEL ====================
		report += "## SBAT LEVEL (in prebuilt efi file)\n\n"
		report += "```\n" + w.sbatLevel + "\n```\n\n"

		// ==================== SBAT ====================
		report += "## SBAT\n\n"
		report += "Source: " + w.buildPathToUrl(w.sbatPath) + "\n"
		report += "```\n" + w.sbatContent + "\n```\n\n"
		sbatReader := csv.NewReader(strings.NewReader(w.sbatContent))
		records, err := sbatReader.ReadAll()
		_ = records
		if err == nil {
			report += "- [X] CSV Format Check : OK (Caution: Check only csv format, not .sbat format)\n"
		} else {
			success = false
			report += "- [ ] CSV Format Check : **FAILED**: " + err.Error() + "\n"
		}
		report += "\n"

		// ==================== EFI FILES ====================
		prebuiltFiles := map[string]*FileAndHash{}
		for k, v := range w.prebuiltEfiFileHashes {
			prebuiltFiles[k] = v
		}

		for _, file := range w.efiFiles {
			filename := filepath.Base(file.Path)
			prebuilt, found := prebuiltFiles[filename]

			report += fmt.Sprintf("## EFI FILE: %s\n\n", filepath.Base(file.Path))

			report += "- reproduced file: " + file.RelatedPath + "\n"
			report += fmt.Sprintf("- computed hash (sha256) : %s\n", file.ComputedHash)

			if found {
				report += "- prebuilt file: " + w.absPathToUrl(prebuilt.RelatedPath) + "\n"

				delete(prebuiltFiles, filename)
				if prebuilt.Hash == file.ComputedHash {
					report += "- [X] Reproduce: Same hash\n"
				} else {
					success = false
					report += "- [ ] Reproduce: Different hash!!!\n"
					report += "- prebuilt hash: " + prebuilt.Hash + "\n"
					report += "- reproduced hash: " + file.ComputedHash + "\n"
				}
			} else {
				success = false
				report += "- Not Found in prebuilt file!!!\n"
			}

			if file.Hash != "" {
				if file.Hash == file.ComputedHash {
					report += fmt.Sprintf("- hash (sha256) : %s\n", file.Hash)
				} else {
					success = false
					report += fmt.Sprintf("- hash : %s (INCORRECT)\n", file.Hash)
				}
			}
			if file.Sbat == w.sbatContent {
				report += "- [X] sbat : SAME\n"
			} else {
				success = false
				report += "- [ ] sbat : **DIFFERENT!!!**\n"
				report += "```\n" + file.Sbat + "\n```\n"
			}

			if len(file.VendorCert) == 0 {
				success = false
				report += "- **VENDOR CERT IS EMPTY!!!**\n"
			} else {
				efiVendorCert := file.VendorCert
				if len(efiVendorCert) > len(w.vendorCertContent) {
					efiVendorCert = efiVendorCert[:len(w.vendorCertContent)]
				}
				if bytes.Equal(w.vendorCertContent, efiVendorCert) {
					report += "- [X] vendor_cert : SAME\n"
				} else {
					success = false
					report += "- [ ] vendor_cert : **DIFFERENT!!!**\n"

					encoded := pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: efiVendorCert,
					})
					report += "```\n" + string(encoded) + "\n```\n"
				}
			}

			if file.FlagNXCompat {
				report += "- [X] NX Compat: True\n"
			} else {
				success = false
				report += "- [ ] NX Compat: False\n"
			}

			for _, testResult := range file.TestResults {
				if testResult.Result {
					report += "- [X] " + testResult.Name + "\n"
				} else {
					report += "- [ ] " + testResult.Name + "\n"
					report += testResult.Message + "\n"
				}
			}

			report += "\n"
		}

		for _, item := range prebuiltFiles {
			success = false
			report += "## Not Built EFI File: " + item.Name + "\n"
			report += "- [ ] It is prebuilt, but not built as a Dockerfile.\n"
			report += "- hash : " + item.Hash + "\n"
			report += "\n"
		}
	}

	report += "## Patch Files\n"

	if len(w.patchFiles) == 0 {
		report += "- No Patch Files\n"
	} else {
		report += ":robot: Human, “Why patches are being applied?” Please check.\n"
		for _, patch := range w.patchFiles {
			report += fmt.Sprintf("- [%s](%s)\n", patch.Name, w.absPathToUrl(patch.RelatedPath))
		}
	}

done:
	// ==================== RESULT ====================
	report += "\n"
	if success {
		report += "## SUCCESS"
	} else {
		report += "## FAILED"
	}

	return report
}

func hashFileSha256(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := crypto.SHA256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type DummyWriter struct{}

func (d *DummyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
