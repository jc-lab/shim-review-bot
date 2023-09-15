package download

import (
	"flag"
	"fmt"
	"github.com/jc-lab/shim-review-bot/app/config"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/exec"
	"regexp"
)

var (
	githubTreeUrlPattern   = regexp.MustCompile("(https://github\\.com/.+)/tree/([^/]+)(?:/(.+))?")
	bitbucketSrcUrlPattern = regexp.MustCompile("(https://bitbucket\\.org/.+)/src/([^/]+)(?:/(.+))?")
)

type Source struct {
	RepositoryUrl string
	Tag           string
	Directory     string
}

func Main(flagSet *flag.FlagSet, args []string) {
	var configFile string
	var source string
	var dest string

	flagSet.StringVar(&configFile, "config", "", "config file")
	flagSet.StringVar(&source, "source", "", "")
	flagSet.StringVar(&dest, "dest", "", "")
	flagSet.Parse(args)

	if configFile != "" {
		raw, err := os.ReadFile(configFile)
		if err != nil {
			err = fmt.Errorf("config file read failed: %v", err)
			log.Fatalln(err)
		}

		var config config.Config
		if err = yaml.Unmarshal(raw, &config); err != nil {
			err = fmt.Errorf("config file parse failed: %v", err)
			log.Fatalln(err)
		}

		if config.Source != "" {
			source = config.Source
		}
	}

	os.MkdirAll(dest, 0755)

	parsed := ParseSourceUrl(source)
	if parsed != nil {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("git clone %s %s && cd %s && git checkout -f %s", parsed.RepositoryUrl, dest, dest, parsed.Tag))
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Fatalln(err)
		}
		if err := cmd.Wait(); err != nil {
			log.Fatalln(err)
		}

		os.Stdout.WriteString(dest + "/" + parsed.Directory)
	} else {
		log.Printf("invalid url: %s", source)
		os.Exit(1)
	}
}

func ParseSourceUrl(source string) *Source {
	matches := githubTreeUrlPattern.FindStringSubmatch(source)
	if matches == nil {
		matches = bitbucketSrcUrlPattern.FindStringSubmatch(source)
	}
	if matches != nil {
		return &Source{
			RepositoryUrl: matches[1] + ".git",
			Tag:           matches[2],
			Directory:     matches[3],
		}
	}
	return nil
}
