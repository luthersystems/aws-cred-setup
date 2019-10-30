# aws-cred-setup

This tool helps configures MFA for your aws credentials securely in the terminal
using the AWS API.

## Prerequisites

You must first configure your AWS credentials with `aws configure` or manually.

This doc assumes your GOPATH is `~/go` (`go env GOPATH` returns
`/Users/username/go`)

## Installation

```
mkdir -p ~/go/src/bitbucket.org/luthersystems
cd ~/go/src/bitbucket.org/luthersystems
git clone git@bitbucket.org:luthersystems/aws-cred-setup.git
# install dependencies - this will probably take a little while
go get -v bitbucket.org/luthersystems/aws-cred-setup
```

## Usage

```
~/go/bin/aws-cred-setup init
```
