package download

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
)

var (
	githubTreeUrlPattern = regexp.MustCompile("(https://github\\.com/.+)/tree/([^/]+)(?:/(.+))?")
)

func Main(flagSet *flag.FlagSet, args []string) {
	var source string
	var dest string

	flagSet.StringVar(&source, "source", "", "")
	flagSet.StringVar(&dest, "dest", "", "")
	flagSet.Parse(args)

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
