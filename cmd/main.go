package main

import (
	"flag"
	"fmt"
	"github.com/jc-lab/shim-review-bot/app/download"
	"github.com/jc-lab/shim-review-bot/app/review"
	"os"
)

func usage() {
	fmt.Printf("%s [download/review] ...", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	app := os.Args[1]

	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	if app == "download" {
		download.Main(flagSet, os.Args[2:])
	} else if app == "review" {
		review.Main(flagSet, os.Args[2:])
	} else {
		usage()
	}
}
