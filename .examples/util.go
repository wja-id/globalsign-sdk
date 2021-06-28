package main

import (
	"io"
	"os"
)

// MapReader .
type MapReader struct {
	m map[string]interface{}
}

func (m *MapReader) String(key string, def ...string) string {
	if len(def) == 0 {
		def = []string{""}
	}

	v, ok := m.m[key]
	if !ok {
		return def[0]
	}

	vv, ok := v.(string)
	if !ok {
		return def[0]
	}

	return vv
}

// NewMapReader .
func NewMapReader(m map[string]interface{}) *MapReader {
	return &MapReader{m: flatten(m)}
}

func flatten(value interface{}) map[string]interface{} {
	return flattenPrefixed(value, "")
}

func flattenPrefixed(value interface{}, prefix string) map[string]interface{} {
	m := make(map[string]interface{})
	flattenPrefixedToResult(value, prefix, m)
	return m
}

func flattenPrefixedToResult(value interface{}, prefix string, m map[string]interface{}) {
	base := ""
	if prefix != "" {
		base = prefix + "."
	}

	cm, ok := value.(map[string]interface{})
	if ok {
		for k, v := range cm {
			flattenPrefixedToResult(v, base+k, m)
		}
	} else {
		if prefix != "" {
			m[prefix] = value
		}
	}
}

// CopyFile the src file to dst. Any existing file will be overwritten and will not
// copy file attributes.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)

	return err
}
