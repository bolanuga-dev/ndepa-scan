package parser

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ParseYAMLOrJSON reads raw byte streams and splits multi-document YAMLs (---)
func ParseYAMLOrJSON(r io.Reader) ([]map[string]interface{}, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read input stream: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var docs []map[string]interface{}

	for {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to decode YAML document: %w", err)
		}
		if len(doc) > 0 {
			docs = append(docs, doc)
		}
	}

	return docs, nil
}
