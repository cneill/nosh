package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"io/ioutil"
)

// Checksums contains the list of hashes for a File
type Checksums struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	CRC32  string `json:"crc32"`
	CRC64  string `json:"crc64"`
}

// GetChecksums returns a Checksums object initialized from the contents supplied
func GetChecksums(contents []byte) Checksums {
	return Checksums{
		MD5:    getChecksumStr(contents, md5.New),
		SHA1:   getChecksumStr(contents, sha1.New),
		SHA256: getChecksumStr(contents, sha256.New),
		CRC32:  fmt.Sprintf("%#x", crc32.ChecksumIEEE(contents)),
		CRC64:  fmt.Sprintf("%#x", crc64.Checksum(contents, crc64.MakeTable(crc64.ISO))),
	}
}

func (c Checksums) String() string {
	var result = "Checksums:\n"
	result += fmt.Sprintf("CRC32 (IEEE): %s\n", c.CRC32)
	result += fmt.Sprintf("CRC64 (ISO): %s\n", c.CRC64)
	result += fmt.Sprintf("MD5: %s\n", c.MD5)
	result += fmt.Sprintf("SHA1: %s\n", c.SHA1)
	result += fmt.Sprintf("SHA256: %s\n", c.SHA256)
	return result
}

func (c Checksums) Digest() string {
	h := sha256.New()
	h.Write([]byte(c.String()))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c Checksums) EqualsDigest(digest string) bool {
	return digest == c.Digest()
}

// ValidateChecksumsFile reads the checksums file and ensures that the downloaded file matches
func (c Checksums) ValidateChecksumsFile(filename string, sumsReader io.Reader) error {
	sumsBytes, err := ioutil.ReadAll(sumsReader)
	if err != nil {
		return fmt.Errorf("failed to read checksums file: %v", err)
	}

	sums, err := getChecksums(sumsBytes)
	if err != nil {
		return fmt.Errorf("failed to parse checksums file: %v", err)
	}

	var success bool
	var observed string
	for _, sum := range sums {
		if sum.filename == filename {
			switch sum.sumtype {
			case md5Sum:
				observed = c.MD5
			case sha1Sum:
				observed = c.SHA1
			case sha256Sum:
				observed = c.SHA256
			}
			if observed == sum.sum {
				success = true
				break
			} else {
				return fmt.Errorf("checksum didn't match: expected %q, got %q", sum.sum, observed)
			}
		}
	}

	if !success {
		return fmt.Errorf("filename %q not found in sums file", filename)
	}
	return nil
}

type ckFunc func() hash.Hash

func getChecksumStr(content []byte, ckFunc ckFunc) string {
	c := ckFunc()
	if _, err := c.Write(content); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", c.Sum(nil))
}

type checksumType int

const (
	md5Sum checksumType = iota
	sha1Sum
	sha256Sum
)

type fileSum struct {
	sumtype  checksumType
	sum      string
	filename string
}

func getChecksums(contents []byte) ([]fileSum, error) {
	var results = []fileSum{}
	s := bufio.NewScanner(bytes.NewReader(contents))
	s.Split(bufio.ScanWords)
	var scanSum = true
	var c = fileSum{}
	for success := s.Scan(); success; success = s.Scan() {
		txt := s.Text()
		if scanSum {
			scanSum = false
			c.sum = txt
			switch len(txt) {
			case 32:
				c.sumtype = md5Sum
			case 40:
				c.sumtype = sha1Sum
			case 64:
				c.sumtype = sha256Sum
			default:
				return nil, fmt.Errorf("unknown sum type")
			}
		} else {
			scanSum = true
			c.filename = txt
			results = append(results, c)
			c = fileSum{}
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("failed to read checksums: %v", err)
	}
	return results, nil
}
