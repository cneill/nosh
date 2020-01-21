package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// Commands:
// - info (print checksums/etc)
// - echo (echo file contents if it validates)
// - exec (run the supplied script if it validates)
// - write (write the file to disk if it validates)

func setupFlags(opts *ClientOpts) {
	flag.Usage = func() {
		fmt.Println("Usage: nosh [OPTIONS] URL")
		flag.PrintDefaults()
	}
	flag.StringVar(&opts.CABundle, "caBundle", "", "bundle of root certificates to trust for SSL verification")
	flag.StringVar(&opts.ChecksumFile, "checksumfile", "", "checksum file (local or http/https)")
	flag.BoolVar(&opts.GenerateCommand, "generateCommand", false, "generate the command to use when noshing in the future")
	flag.BoolVar(&opts.GenerateCommand, "g", false, "(short) generate the command to use when noshing in the future")
	flag.BoolVar(&opts.InfoOnly, "infoOnly", false, "print info and quit")
	flag.BoolVar(&opts.InfoOnly, "i", false, "(short) print info and quit")
	flag.StringVar(&opts.OutFile, "outFile", "", "file to write contents to")
	flag.StringVar(&opts.OutFile, "o", "", "(short) file to write contents to")
	flag.StringVar(&opts.NoshDigest, "noshDigest", "", "nosh digest to compare against")
	flag.StringVar(&opts.NoshDigest, "n", "", "(short) nosh digest to compare against")
	flag.StringVar(&opts.SHA1, "sha1", "", "sha1 hash for the file")
	flag.StringVar(&opts.SHA256, "sha256", "", "sha256 hash for the file")
	flag.BoolVar(&opts.Verbose, "verbose", false, "toggle verbosity")
	flag.BoolVar(&opts.Verbose, "v", false, "(short) toggle verbosity")
	// TODO: SSL-only
}

func parseFlags(opts *ClientOpts) {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Printf("echo 'Must provide a URL to test.'")
		os.Exit(0)
	}

	if opts.InfoOnly && opts.GenerateCommand {
		fmt.Printf("echo \"Can't specify both infoOnly and generateCommand\"")
		os.Exit(0)
	}

	if opts.InfoOnly {
		opts.Verbose = true
	}
}

func main() {
	opts := DefaultOpts()
	setupFlags(opts)
	parseFlags(opts)
	c, err := NewClient(opts)
	if err != nil {
		log.Fatalf("error initializing client: %v", err)
	}
	defer c.Teardown()
	if err := c.Setup(); err != nil {
		log.Fatalf("error setting up client: %v", err)
	}
	url := flag.Args()[0]
	c.RetrieveFile(url)
	if opts.InfoOnly {
		c.PrintInfo()
	} else if opts.GenerateCommand {
		c.GenerateCommandString()
	} else {
		c.OutputIfValidates()
	}
}
