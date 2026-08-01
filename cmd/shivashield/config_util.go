package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func updateGeoBlockConfig(path, action, cc string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}

	if len(root.Content) == 0 {
		return fmt.Errorf("empty yaml")
	}

	mapping := root.Content[0]
	for i := 0; i < len(mapping.Content); i += 2 {
		key := mapping.Content[i]
		val := mapping.Content[i+1]
		if key.Value == "geoip" {
			for j := 0; j < len(val.Content); j += 2 {
				gkey := val.Content[j]
				gval := val.Content[j+1]
				if gkey.Value == "block_countries" {
					if action == "add" {
						for _, n := range gval.Content {
							if n.Value == cc {
								return nil // already exists
							}
						}
						gval.Content = append(gval.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: cc})
					} else if action == "remove" {
						var newContent []*yaml.Node
						for _, n := range gval.Content {
							if n.Value != cc {
								newContent = append(newContent, n)
							}
						}
						gval.Content = newContent
					}
					break
				}
			}
			break
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}
