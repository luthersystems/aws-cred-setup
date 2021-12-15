# aws-cred-setup

This tool helps configures MFA for your aws credentials securely in the terminal
using the AWS API.

## Prerequisites

You must first configure your AWS credentials with `aws configure` or manually.

This doc assumes your GOPATH is `~/go` (`go env GOPATH` returns
`/Users/username/go`)

## Installation

```
go install bitbucket.org/luthersystems/aws-cred-setup@latest
```

## Usage

```
~/go/bin/aws-cred-setup init
```
