# nosh

## About

Everyone curl-bashes scripts sometimes. But do you really know what you're mashing into a (possibly privileged) shell? nosh
will help you validate that the script you received is the one you expected. If the checksums don't match, an error describing
what failed will be harmlessly echo'd by the shell.

:x: Warning: this is hacky. I'm only releasing it to goad myself into improving it. Feel free to share any ideas by raising a
GitHub issue. :x:

## Install

`go install github.com/cneill/nosh`

## Usage

`./nosh --help` will print the help message:

```
Usage: nosh [OPTIONS] URL
  -caBundle string
        bundle of root certificates to trust for SSL verification
  -checksumfile string
        checksum file (local or http/https)
  -g    (short) generate the command to use when noshing in the future
  -generateCommand
        generate the command to use when noshing in the future
  -i    (short) print info and quit
  -infoOnly
        print info and quit
  -n string
        (short) nosh digest to compare against
  -noshDigest string
        nosh digest to compare against
  -o string
        (short) file to write contents to
  -outFile string
        file to write contents to
  -sha1 string
        sha1 hash for the file
  -sha256 string
        sha256 hash for the file
  -v    (short) toggle verbosity
  -verbose
        toggle verbosity
```

## Examples

__Get the nosh command to use:__

`nosh -g https://example.com`

__Get info about a file:__

`nosh -i https://example.com`

__Verify a file against its SHA256 checksum:__

`nosh -sha256 d6b366ce2dfe5de61d0e085055c576407a8fc014a60137bc0fdbe474fb3ef90a https://example.com | sh`

__Use a specific CA bundle to validate SSL certificate of remote server:__

`nosh -caBundle /path/to/bundle.pem https://example.com | sh`

## License

Copyright (c) 2020 Charles Neill. All rights reserved. nosh is distributed under an open-source [BSD license](./LICENSE.md).
