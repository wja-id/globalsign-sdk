## Globalsign DSS client SDK 

a client SDK for communicatiing with globalsign DSS (digital signing service) 

for [unidoc](https://unidoc.io "Unidoc website") integration see **integration** package

```go 
...

// Create signature handler.
handler, err := integration.NewGlobalSignDSS(context.Background(), option.SignedBy)
if err != nil {
    return err
}

// Create signature.
signature := model.NewPdfSignature(handler) 
...

```