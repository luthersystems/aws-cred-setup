# Prerequisites

It it assumed you have configured your AWS credentials with `aws configure` or
similar.

# Installation

```
mkdir -p "$(go env GOPATH)/src/bitbucket.org/luthersystems"
cd "$(go env GOPATH)/src/bitbucket.org/luthersystems"
git clone git@bitbucket.org:luthersystems/aws-cred-setup.git
go install bitbucket.org/luthersystems/aws-cred-setup
```

# Usage

```
aws-cred-setup init
```
