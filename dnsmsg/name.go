package dnsmsg

import (
	"fmt"
	"strings"
)

const maxNameLength = 255
const maxLabelLength = 63

// encodeName converts a dotted domain name (e.g. "example.com" or the root
// ".") into its wire-format representation: length-prefixed labels
// terminated by a zero-length label. It does not use name compression.
func encodeName(name string) ([]byte, error) {
	if len(name) > maxNameLength {
		return nil, fmt.Errorf("name too long: %q", name)
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}

	labels := strings.Split(name, ".")
	buf := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if len(label) == 0 || len(label) > maxLabelLength {
			return nil, fmt.Errorf("invalid label %q in name %q", label, name)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	return buf, nil
}
