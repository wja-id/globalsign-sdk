# Pdf Signer 
an example POC of pdf signer which leverage unipdf and globalsign DSS

#### Go Setup

Please refer to  https://golang.org/doc/install

#### Unidoc License 

Retrive your free trial license from https://www.unidoc.io/free-trial

1. if you are planning to use environment variables
create file .unidoc and paste your license key into then export .unidoc file path to `$UNIDOC_LICENSE_PATH`

```
$ vi .unidoc
$ export UNIDOC_LICENSE_PATH=<path to .unidoc>
```
and export company name which license registered to 

```
$ export UNIDOC_COMPANY_NAME="My Company"
```

2. directly modify the code 

Please put license key and company name into this line of code 
```go
// unipdf license
var (
	licenseKey  = ""
	companyName = ""
)
```

#### Update dependencies (go module)

Please download required dependencies

```
$ go mod download
```

#### Build the code

```
$ go build
```

or with environment variable 

```
$ chmod +x build.sh
$ ./build.sh  
```

#### Execute 

```
$ ./pdf-signer -input-file "cover.pdf" -output-file "cover-signed.pdf" -api-key API_KEY -api-secret API_SECRET -cert-file mTLS.cer -key-file key.pem -email glen@igopher.net
```

#
#
#####Notes:
bash file with suffix darwin, windows are used to cross-compile this test program into another OS 

