package main

import (
	"fmt"
	"os"
)

// File wraps an os.File object to hold hashes and other additional info
type File struct {
	*os.File
	Filename  string
	Bytes     []byte
	Checksums Checksums
	Tempfile  bool
}

// NewFile returns an initialized File object
func NewFile(f *os.File, tempfile bool) *File {
	return &File{
		File:      f,
		Bytes:     []byte{},
		Checksums: Checksums{},
		Tempfile:  tempfile,
	}
}

// SetContent writes the file to disk and gathers information about the content
func (f *File) SetContent(content []byte) error {
	f.Bytes = content
	_, err := f.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}
	f.Checksums = GetChecksums(content)
	return nil
}

// Delete removes the file from disk
func (f *File) Delete() error {
	if err := os.Remove(f.Name()); err != nil {
		return fmt.Errorf("failed to delete tempfile %q: %v", f.Name(), err)
	}
	return nil
}
