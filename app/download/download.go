package download

import (
	"flag"
	"fmt"
	"github.com/jc-lab/shim-review-bot/app/review"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/exec"
	"regexp"
)

var (
	githubTreeUrlPattern = regexp.MustCompile("(https://github\\.com/.+)/tree/([^/]+)(?:/(.+))?")
)

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

		var config review.Config
		if err = yaml.Unmarshal(raw, &config); err != nil {
			err = fmt.Errorf("config file parse failed: %v", err)
			log.Fatalln(err)
		}

		if config.Source != "" {
			source = config.Source
		}
	}

	os.MkdirAll(dest, 0755)

	matches := githubTreeUrlPattern.FindStringSubmatch(source)

	if len(matches) > 0 {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("git clone %s %s && cd %s && git checkout -f %s", matches[1], dest, dest, matches[2]))
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Fatalln(err)
		}
		if err := cmd.Wait(); err != nil {
			log.Fatalln(err)
		}

		os.Stdout.WriteString(dest + "/" + matches[3])
	} else {
		log.Printf("invalid url: %s", source)
		os.Exit(1)
	}
}
