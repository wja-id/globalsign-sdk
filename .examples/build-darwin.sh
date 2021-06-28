#!/bin/bash

# build plugin mode
GOOS=darwin \
GOARCH=amd64 \
go build \
-ldflags "-s -w" \
-ldflags="-X 'main.licenseKey=$(cat $UNIDOC_LICENSE_PATH)' -X 'main.companyName=$(echo $UNIDOC_COMPANY_NAME)'" \
-o pdf-signer-darwin


