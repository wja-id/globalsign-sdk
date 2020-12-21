## Globalsign DSS client SDK 

a client SDK for communicatiing with globalsign DSS (digital signing service) 

for [unidoc](https://unidoc.io "Unidoc website") integration see **integration** package

```go 
...

// create globalsign manager
manager, err := globalsign.NewManager(&globalsign.ManagerOption{
	APIKey:             "<API KEY>",
	APISecret:          "<API SECRET>",
	BaseURL:            "<BASE_URL>",
	PrivateKeyPath:     "<KEY_PATH>",
	TLSCertificatePath: "<CERT_PATH>",
})
if err != nil {
	return err
}

// Create signature handler.
handler, err := integration.NewGlobalSignDSS(context.Background(), manager, option.SignedBy, map[string]interface{}{
	"common_name": "Galih Rivanto"
})
if err != nil {
	return err
}

// Create signature.
signature := model.NewPdfSignature(handler) 
...

```