# aws-cred-setup

This tool helps configures MFA for your aws credentials securely in the terminal
using the AWS API.

## Prerequisites

You must first configure your AWS credentials with `aws configure` or manually.
The tool must run as the IAM user itself, not a role. By default it reads only
the environment, `AWS_PROFILE`, `AWS_REGION` and `~/.aws/credentials`, so a role
profile in `~/.aws/config` does not replace your keys. Set
`AWS_SDK_LOAD_CONFIG=1` to read `~/.aws/config` too.

This doc assumes your GOPATH is `~/go` (`go env GOPATH` returns
`/Users/username/go`)

## Installation

```
go install github.com/luthersystems/aws-cred-setup@latest
```

## Usage

```
~/go/bin/aws-cred-setup init
```
