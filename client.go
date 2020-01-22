package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ClientOpts sets various configuration settings in Client
type ClientOpts struct {
	InfoOnly        bool
	GenerateCommand bool
	OutFile         string
	SHA1            string
	SHA256          string
	NoshHash        string
	ChecksumFile    string
	UserAgent       string
	CABundle        string
	Verbose         bool
}

// DefaultOpts returns the default ClientOpts object
func DefaultOpts() *ClientOpts {
	return &ClientOpts{
		UserAgent: "curl/7.58.0",
	}
}

// Client handles retrieving files and validating them
type Client struct {
	*http.Client
	*ClientOpts

	Out   *log.Logger
	Error *log.Logger
	Info  *log.Logger

	FileURL *url.URL
	File    *File
}

// NewClient returns an initialized Client
func NewClient(opts *ClientOpts) (*Client, error) {
	// TODO: verify against custom CA bundle

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLSv1.3
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,

			// TLSv1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	if opts.CABundle != "" {
		caBundleContents, err := ioutil.ReadFile(opts.CABundle)
		if err != nil {
			return nil, err
		}

		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caBundleContents); !ok {
			return nil, fmt.Errorf("failed to parse any certificates from provided CA bundle %q", opts.CABundle)
		}

		tlsConf.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConf,
	}

	c := &http.Client{
		Transport: transport,
	}

	var infoOut = ioutil.Discard
	if opts.Verbose {
		infoOut = os.Stderr
	}

	return &Client{
		Client:     c,
		ClientOpts: opts,

		Out:   log.New(os.Stderr, "", 0),
		Error: log.New(os.Stderr, "[error]\t", 0),
		Info:  log.New(infoOut, "[info]\t", 0),
	}, nil
}

// Setup performs setup steps like opening the output file for writing, once the Client is initialized
func (c *Client) Setup() error {
	if err := c.OpenOutfile(); err != nil {
		return fmt.Errorf("failed to open out file: %v", err)
	}

	c.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		c.Info.Printf("Redirected to URL: %s\n", req.URL.String())
		return nil
	}

	return nil
}

// Teardown deletes the downloaded file
func (c *Client) Teardown() {
	if c.File.Tempfile {
		if err := c.File.Delete(); err != nil {
			fmt.Printf("error: %v", err)
		} else {
			c.Info.Printf("Deleted tempfile %q\n", c.File.Name())
		}
	}
}

// OpenOutfile opens the os.File object, either in the specified out file, or a temp file
func (c *Client) OpenOutfile() error {
	var f *os.File
	var err error
	var tempfile = true

	if c.OutFile == "" {
		f, err = ioutil.TempFile("/tmp", "outfile")
	} else {
		f, err = os.OpenFile(c.OutFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		tempfile = false
	}
	c.errh(err)
	c.File = NewFile(f, tempfile)
	return nil
}

// RetrieveFile downloads the file, and writes it to the configured file
func (c *Client) RetrieveFile(URL string) {
	// make sure we close outFile no matter what
	defer c.File.Close()
	parsed, err := url.Parse(URL)
	c.errh(err)
	c.File.Filename = filepath.Base(parsed.Path)
	c.FileURL = parsed

	c.Info.Printf("Requesting URL: %s\n", URL)
	req, err := c.newRequest("GET", URL)
	c.errh(err)
	resp, err := c.Do(req)
	c.errh(err)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	c.errh(err)
	c.Info.Printf("Writing to file %q\n", c.File.Name())
	c.errh(c.File.SetContent(bodyBytes[:]))
}

// Validate ensures that validation flags like -sha256 are satisfied
func (c *Client) Validate() error {
	// TODO: WHEN THESE FAIL, DON'T WRITE TO FILE, OR DELETE FILE WHEN CLOSING NOSH
	var errors = []string{}

	if c.File == nil {
		return fmt.Errorf("file was nil")
	} else if c.File.Filename == "" {
		return fmt.Errorf("file name wasn't set")
	}

	if c.SHA1 != "" && c.SHA1 != c.File.Checksums.SHA1 {
		errors = append(errors, fmt.Sprintf("\tSHA1 did not validate; expected: %q, received: %q", c.SHA1, c.File.Checksums.SHA1))
	}

	if c.SHA256 != "" && c.SHA256 != c.File.Checksums.SHA256 {
		errors = append(errors, fmt.Sprintf("\tSHA256 did not validate; expected: %q, received: %q", c.SHA256, c.File.Checksums.SHA256))
	}

	if c.NoshHash != "" && !c.File.Checksums.EqualsDigest(c.NoshHash) {
		errors = append(errors, fmt.Sprintf("\tnosh Digest did not validate; expected: %q, received %q", c.NoshHash, c.File.Checksums.Digest()))
	}

	if c.ChecksumFile != "" {
		if err := c.ValidateChecksumsFile(); err != nil {
			errors = append(errors, fmt.Sprintf("\tchecksums file did not validate: %v", err))
		}
	}

	if len(errors) > 0 {
		errStr := strings.Join(errors, "\n")
		return fmt.Errorf("%s", errStr)
	}

	return nil
}

// ValidateChecksumsFile reads the specified checksums file and searches for the downloaded file's hash
func (c *Client) ValidateChecksumsFile() error {
	if c.ChecksumFile == "" {
		return fmt.Errorf("no checksum file specified")
	}
	var reader io.ReadCloser

	parsed, err := url.Parse(c.ChecksumFile)
	if err != nil {
		return fmt.Errorf("checksum file path/URL could not be parsed: %v", err)
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		resp, err := c.Get(parsed.String())
		if err != nil {
			return fmt.Errorf("failed to retrieve checksums file: %v", err)
		}
		reader = resp.Body
	} else if parsed.Scheme == "" {
		f, err := os.OpenFile(c.ChecksumFile, os.O_RDONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open checksums file: %v", err)
		}
		reader = f
	} else {
		return fmt.Errorf("checksum file path/URL had invalid scheme: %s (must be http/https, or local path)", parsed.Scheme)
	}

	defer reader.Close()
	return c.File.Checksums.ValidateChecksumsFile(c.File.Filename, reader)
}

// PrintInfo prints the hashes and number of bytes
func (c *Client) PrintInfo() {
	c.Info.Printf("%s", c.File.Checksums.String())
	c.Info.Printf("Bytes: %d", len(c.File.Bytes))
	c.Info.Printf("nosh Digest: %s", c.File.Checksums.Digest())
}

func (c *Client) GenerateCommandString() {
	c.Out.Printf("nosh -n %q %q", c.File.Checksums.Digest(), c.FileURL.String())
}

// OutputIfValidates prints the contents of the file to stdout if it validates
func (c *Client) OutputIfValidates() {
	if err := c.Validate(); err != nil {
		c.PrintInfo()
		fmt.Printf("echo 'File did not pass validation:\n%v'; exit 1", err)
	} else {
		fmt.Printf("%s", c.File.Bytes)
	}
}

func (c *Client) newRequest(method, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)

	return req, nil
}

func (c *Client) errh(err error) {
	if err != nil {
		c.Error.Fatalf("%v", err)
	}
}
