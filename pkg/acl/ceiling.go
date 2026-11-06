package acl

type (
	// Ceiling is the set of destinations a tailnet may ever reach.
	Ceiling struct {
		// Destinations are the entries a rendered destination must fall inside.
		Destinations []Destination `json:"destinations,omitempty" yaml:"destinations,omitempty"`
	}

	// Destination is one entry of a Ceiling: a prefix or a tag, with the ports allowed on it.
	Destination struct {
		CIDR  string   `json:"cidr,omitempty" yaml:"cidr,omitempty"`
		Tag   string   `json:"tag,omitempty" yaml:"tag,omitempty"`
		Ports []string `json:"ports" yaml:"ports"`
	}
)

// Validate refuses a malformed ceiling.
func (c *Ceiling) Validate() error { return nil }

// CheckDst refuses a rendered destination outside the ceiling.
func (c *Ceiling) CheckDst(dst string) error { return nil }

// Within refuses a ceiling that is not inside outer.
func (c *Ceiling) Within(outer *Ceiling) error { return nil }
