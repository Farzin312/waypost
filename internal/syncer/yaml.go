package syncer

import (
	"bytes"
	"errors"

	"github.com/Farzin312/waypost/internal/config"
	"gopkg.in/yaml.v3"
)

type configDocument struct{ root *yaml.Node }

func parseDocument(raw []byte) (configDocument, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return configDocument{}, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return configDocument{}, errors.New("config root must be a YAML mapping")
	}
	return configDocument{root: doc.Content[0]}, nil
}

func (d configDocument) marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d.root); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

func findField(m *yaml.Node, name string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == name {
			return m.Content[i+1]
		}
	}
	return nil
}

func addField(m *yaml.Node, key string, value *yaml.Node) {
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func setString(m *yaml.Node, key, value string) bool {
	n := findField(m, key)
	if n == nil {
		addField(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
		return true
	}
	if n.Anchor != "" {
		return false
	}
	n.Kind, n.Tag, n.Value, n.Alias = yaml.ScalarNode, "!!str", value, nil
	return true
}

func (d configDocument) sequence(key string) (*yaml.Node, bool) {
	seq := findField(d.root, key)
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		addField(d.root, key, seq)
	}
	return seq, seq.Kind == yaml.SequenceNode && seq.Anchor == ""
}

func (d configDocument) removeComponent(id string) bool {
	seq := findField(d.root, "components")
	if seq == nil || seq.Kind != yaml.SequenceNode || seq.Anchor != "" {
		return false
	}
	for i, item := range seq.Content {
		if field := findField(item, "id"); field != nil && field.Value == id && item.Anchor == "" {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			return true
		}
	}
	return false
}

func (d configDocument) updatePin(id, version string) bool {
	seq := findField(d.root, "pins")
	if seq == nil || seq.Kind != yaml.SequenceNode || seq.Anchor != "" {
		return false
	}
	for _, item := range seq.Content {
		if field := findField(item, "id"); field != nil && field.Value == id && item.Anchor == "" {
			return setString(item, "version", version)
		}
	}
	return false
}

func appendComponent(seq *yaml.Node, c config.ComponentConfig) error {
	var n yaml.Node
	if err := n.Encode(c); err != nil {
		return err
	}
	seq.Content = append(seq.Content, &n)
	return nil
}

func (d configDocument) graduate() bool {
	b := findField(d.root, "boundaries")
	if b == nil {
		b = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		addField(d.root, "boundaries", b)
	}
	return b.Kind == yaml.MappingNode && b.Anchor == "" && setString(b, "mode", "enforce")
}
