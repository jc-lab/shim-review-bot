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

type ExportedFile struct {
	Path string
	Hash string
}

type EfiFile struct {
	Name               string
	Hash               string
	ComputedHash       string
	Sbat               string
	VendorCert         []byte
	VendorDeAuthorized []byte
}

type WorkingContext struct {
	vendorCert []byte
	sbat       string

	outputState   outputState
	hashes        []*HashSum
	exportedFiles []*ExportedFile

	efiFiles []*EfiFile

	buildErr error
	otherErr error
}

func Main(flagSet *flag.FlagSet, args []string) {
	var buildCommand string
	var outputFile string
	var reportFile string
	var vendorCert string
	var sbat string

	flagSet.StringVar(&buildCommand, "build-script", "", "build-script file")
	flagSet.StringVar(&outputFile, "output-file", "", "docker output file (tar)")
	flagSet.StringVar(&vendorCert, "vendor-cert", "vendor_cert.der", "vendor cert der file")
	flagSet.StringVar(&sbat, "sbat", "sbat.csv", "vendor cert der file")

	flagSet.StringVar(&reportFile, "report-output", "", "report output file")
	flagSet.Parse(args)

	var workingContext WorkingContext
	var sbatRaw []byte
	var tempDir string

	workingContext.vendorCert, workingContext.otherErr = os.ReadFile(vendorCert)
	if workingContext.otherErr != nil {
		log.Printf("vendor_cert open failed: %v", workingContext.otherErr)
		goto done
	}

	sbatRaw, workingContext.otherErr = os.ReadFile(sbat)
	if workingContext.otherErr != nil {
		log.Printf("sbat.csv open failed: %v", workingContext.otherErr)
		goto done
	}
	workingContext.sbat = string(sbatRaw)

	workingContext.buildErr = workingContext.build(buildCommand)
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
			Name:         basename,
			Hash:         item.Hash,
			ComputedHash: computedHash,
		}

		peFile, err := pe.Open(item.Path)
		if err != nil {
			log.Printf("efi(%s) open failed: %v", item.Path, err)
			continue
		}
		defer peFile.Close()

		sbat := peFile.Section(".sbat")
		if sbat != nil {
			raw, err := sbat.Data()
			if err != nil {
				log.Printf("sbat read failed: %v", err)
			} else {
				nullPos := bytes.IndexByte(raw, 0)
				if nullPos > 0 {
					raw = raw[:nullPos]
				}
				efiFile.Sbat = string(raw)
			}
		}
		certTableSection := peFile.Section(".vendor_cert")
		if certTableSection != nil {
			raw, err := certTableSection.Data()
			if err != nil {
				log.Printf("vendor_cert read failed: %v", err)
			} else {
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

func (w *WorkingContext) build(buildCommand string) error {
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

	go func() {
		reader := io.TeeReader(stderr, os.Stderr)
		w.handleOutput(reader)
	}()
	go func() {
		reader := io.TeeReader(stdout, os.Stdout)
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

		var hashEntry *HashSum
		for _, s := range w.hashes {
			if s.Path[1:] == header.Name {
				hashEntry = s
			}
		}

		if hashEntry != nil {
			destFileName := filepath.Join(outputDirectory, filepath.Base(header.Name))
			f, err := os.OpenFile(destFileName, os.O_CREATE|os.O_RDWR, 0644)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err = io.Copy(f, reader); err != nil {
				return err
			}

			w.exportedFiles = append(w.exportedFiles, &ExportedFile{
				Path: destFileName,
				Hash: hashEntry.Hash,
			})
		} else {
			if _, err = io.Copy(&DummyWriter{}, reader); err != nil {
				return err
			}
		}
	}

	return nil
}

func (w *WorkingContext) buildReport() string {
	report := ""
	success := true

	if w.buildErr != nil {
		report += "## BUILD ERROR\n\n"
		report += "```\n"
		report += w.buildErr.Error()
		report += "\n```\n"
	}
	if w.otherErr != nil {
		report += "## REVIEW ERROR\n\n"
		report += "```\n"
		report += w.otherErr.Error()
		report += "\n```\n"
	}

	// ==================== VENDOR CERTIFICATE ====================
	report += "## vendor certificate\n\n"
	cert, err := x509.ParseCertificate(w.vendorCert)
	if err != nil {
		success = false
		report += "ERROR: " + err.Error() + "\n"
	} else {
		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: w.vendorCert,
		})
		report += "PEM: \n```\n" + string(encoded) + "\n```\n\n"
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
			report += "- [ ] ExtKeyUsage/CodeSigning : **NO DigitalSignature in Key Usage!!!**\n"
		}
	}
	report += "\n"

	// ==================== SBAT ====================
	report += "## SBAT\n\n"
	report += "```\n" + w.sbat + "\n```\n\n"
	sbatReader := csv.NewReader(strings.NewReader(w.sbat))
	records, err := sbatReader.ReadAll()
	_ = records
	if err == nil {
		report += "- CSV Format Check : OK (Caution: Check only csv format, not sbat format)\n"
	} else {
		success = false
		report += "- CSV Format Check : **FAILED**: " + err.Error() + "\n"
	}
	report += "\n"

	// ==================== EFI FILES ====================
	for _, file := range w.efiFiles {
		report += fmt.Sprintf("## EFI FILE: %s\n\n", filepath.Base(file.Name))
		if file.Hash == file.ComputedHash {
			report += fmt.Sprintf("- hash (sha256) : %s\n", file.Hash)
		} else {
			success = false
			report += fmt.Sprintf("- hash : %s (INCORRECT)\n", file.Hash)
			report += fmt.Sprintf("- computed hash (sha256) : %s\n", file.ComputedHash)
		}
		if file.Sbat == w.sbat {
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
			if len(efiVendorCert) > len(w.vendorCert) {
				efiVendorCert = efiVendorCert[:len(w.vendorCert)]
			}
			if bytes.Equal(w.vendorCert, efiVendorCert) {
				report += "- [X] vendor_cert : SAME\n"
			} else {
				success = false
				report += "- [ ] vendor_cert : **DIFFERENT!!!**\n"

				encoded := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: efiVendorCert,
				})
				report += "PEM: \n```\n" + string(encoded) + "\n```\n"
			}
		}
		report += "\n"
	}

	// ==================== RESULT ====================
	report += "\n"
	if success {
		report += "**SUCCESS**"
	} else {
		report += "**FAILED**"
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
