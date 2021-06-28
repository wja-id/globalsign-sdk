#!/bin/bash

# build plugin mode
go build \
-ldflags "-s -w" \
-ldflags="-X 'main.licenseKey=$(cat $UNIDOC_LICENSE_PATH)' -X 'main.companyName=$(echo $UNIDOC_COMPANY_NAME)'" \
-o pdf-signer-linux


