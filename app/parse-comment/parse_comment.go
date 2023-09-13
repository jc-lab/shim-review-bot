package parse_comment

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

func Main(flagSet *flag.FlagSet, args []string) {
	var commentFile string
	var configFile string
	flagSet.StringVar(&commentFile, "comment-file", "", "issue comment file")
	flagSet.StringVar(&configFile, "config", "", "output config file")
	flagSet.Parse(args)

	commentRaw, err := os.ReadFile(commentFile)
	if err != nil {
		err = fmt.Errorf("comment file read failed: %v", err)
		log.Fatalln(err)
	}

	parsed, err := CommentParse(string(commentRaw))
	if err != nil {
		err = fmt.Errorf("comment file parse failed: %v", err)
		log.Fatalln(err)
	}

	encoded, err := yaml.Marshal(parsed.Config)
	if err != nil {
		log.Fatalln(err)
	}
	if err := os.WriteFile(configFile, encoded, 0644); err != nil {
		log.Fatalln(err)
	}
}
