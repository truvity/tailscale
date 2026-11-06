package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	tagPrefix = "tag:"
	portMin   = 1
	portMax   = 65535
)

type (
	// Ceiling is the set of destinations one tailnet may ever reach: the
	// outer bound a rendered rule must stay inside, whoever asked for the
	// rule. It is a bound, never a grant: it refuses a destination outside
	// it and it never adds a rule, rewrites one or clips one.
	//
	// The zero value is a ceiling that admits nothing. A nil *Ceiling is "no
	// ceiling" to the code that holds an optional one, but a nil receiver on
	// the methods below fails closed: CheckDst refuses and Within refuses.
	//
	// A destination is admitted by the entries that contain it, never by a
	// union of entries that each cover part of it: a /16 is not admitted by
	// two entries that are its two /17 halves. Name the prefix the rules
	// actually use.
	Ceiling struct {
		// Destinations are the entries a rendered destination must fall
		// inside. Empty admits nothing.
		Destinations []Destination `json:"destinations,omitempty" yaml:"destinations,omitempty"`
	}

	// Destination is one entry of a Ceiling: exactly one of CIDR or Tag, and
	// the ports allowed on it.
	Destination struct {
		// CIDR is a canonical prefix ("10.0.0.0/16", never "10.0.0.1/16"). A
		// single host is spelled as a /32 (or /128). It admits every
		// destination prefix inside it.
		CIDR string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
		// Tag is a tag name without the "tag:" prefix. It admits that tag.
		Tag string `json:"tag,omitempty" yaml:"tag,omitempty"`
		// Ports is required: "*", a port "443" or a range "8000-8100", each
		// within 1-65535. There is no default, for the reason Grant has
		// none: an entry with no port list would admit every port.
		Ports []string `json:"ports" yaml:"ports"`
	}

	// portRange is an inclusive range of ports.
	portRange struct{ lo, hi int }

	// portSet is a sorted, merged set of ports.
	portSet []portRange

	// entry is a validated Destination.
	entry struct {
		prefix netip.Prefix // valid for a CIDR entry
		tag    string       // set for a tag entry
		ports  portSet
		text   string // "10.0.0.0/16" or "tag:x"
		spec   string // the entry's ports as written, comma-joined
	}

	// target is one parsed destination: what a rule, or a requested
	// ceiling's entry, asks to reach.
	target struct {
		prefix netip.Prefix
		tag    string
		ports  portSet
		text   string // the target without its ports
	}
)

// Validate refuses a malformed ceiling: an entry with both or neither of
// CIDR and Tag, a CIDR that does not parse or is not canonical, a tag name
// with a prefix, a colon or whitespace in it, an empty port list, a port
// outside 1-65535, a reversed range, a repeated port, or two entries for the
// same prefix or tag. A nil ceiling is not malformed.
func (c *Ceiling) Validate() error {
	if c == nil {
		return nil
	}

	_, err := c.compile()

	return err
}

// CheckDst refuses a rendered destination that is outside the ceiling. dst
// is the form a rule carries, "10.0.0.0/16:*", "10.0.0.5/32:443,8443",
// "tag:x:22" or "2001:db8::/32:443"; the ports are split off at the last
// colon, so an IPv6 prefix works. A prefix is admitted when the entries
// whose prefix contains it, together, allow every port it names; a tag is
// admitted when an entry names it and allows its ports.
//
// It fails closed: anything that is not a canonical prefix or a tag with a
// valid port list ("autogroup:internet:*", "group:x:*", a host name, a bare
// address, a prefix with host bits set) is refused, as is every destination
// when the ceiling is nil, empty or malformed.
func (c *Ceiling) CheckDst(dst string) error {
	if c == nil {
		return fmt.Errorf("acl: destination %s: there is no ceiling to check it against", dst)
	}

	entries, err := c.compile()
	if err != nil {
		return err
	}

	t, err := parseTarget(dst)
	if err != nil {
		return fmt.Errorf("acl: destination %q cannot be checked against the tailnet ceiling: %w", dst, err)
	}

	if why := admit(entries, t); why != "" {
		return fmt.Errorf("acl: destination %s is outside the tailnet ceiling (%s)", dst, why)
	}

	return nil
}

// Within refuses a ceiling that reaches beyond outer: an entry of c that the
// entries of outer do not admit, by the rule CheckDst applies to a
// destination, makes c wider. It is the primitive for refusing a requested
// ceiling that exceeds a registered one. Every offending entry is reported,
// in the order of c.Destinations. A nil c is unbounded and is within nothing;
// a nil outer admits nothing; a malformed ceiling on either side is an error.
func (c *Ceiling) Within(outer *Ceiling) error {
	if c == nil {
		return errors.New("acl: a missing ceiling is unbounded and is not within any ceiling")
	}

	if outer == nil {
		return errors.New("acl: there is no outer ceiling to be within")
	}

	own, err := c.compile()
	if err != nil {
		return err
	}

	bound, err := outer.compile()
	if err != nil {
		return fmt.Errorf("outer ceiling: %w", err)
	}

	var errs []error

	for _, e := range own {
		t := target{prefix: e.prefix, tag: e.tag, ports: e.ports, text: e.text}
		if why := admit(bound, t); why != "" {
			errs = append(errs, fmt.Errorf("acl: ceiling entry %s ports %s is outside the outer ceiling (%s)", e.text, e.spec, why))
		}
	}

	return errors.Join(errs...)
}

// compile validates the ceiling and returns its entries in the order written.
func (c *Ceiling) compile() ([]entry, error) {
	out := make([]entry, 0, len(c.Destinations))
	seen := map[string]bool{}

	for i, d := range c.Destinations {
		e, err := compileDestination(d)
		if err != nil {
			return nil, fmt.Errorf("acl: ceiling destination %d: %w", i, err)
		}

		if seen[e.text] {
			return nil, fmt.Errorf("acl: ceiling destination %d: %s is listed twice", i, e.text)
		}

		seen[e.text] = true

		out = append(out, e)
	}

	return out, nil
}

func compileDestination(d Destination) (entry, error) {
	var e entry

	switch {
	case d.CIDR != "" && d.Tag != "":
		return e, fmt.Errorf("cidr %q and tag %q: exactly one is allowed", d.CIDR, d.Tag)
	case d.CIDR == "" && d.Tag == "":
		return e, errors.New("needs a cidr or a tag")
	case d.CIDR != "":
		p, err := parsePrefix(d.CIDR)
		if err != nil {
			return e, err
		}

		e.prefix, e.text = p, d.CIDR
	default:
		if err := checkTagName(d.Tag); err != nil {
			return e, err
		}

		e.tag, e.text = d.Tag, tagPrefix+d.Tag
	}

	if len(d.Ports) == 0 {
		return e, fmt.Errorf("%s has no ports: an entry with no port list would admit every port, so it is refused rather than defaulted", e.text)
	}

	ports, err := parsePorts(d.Ports, true)
	if err != nil {
		return e, fmt.Errorf("%s: %w", e.text, err)
	}

	e.ports, e.spec = ports, strings.Join(d.Ports, ",")

	return e, nil
}

// parseTarget splits a rendered destination into what it names and its ports.
func parseTarget(dst string) (target, error) {
	i := strings.LastIndex(dst, ":")
	if i < 0 {
		return target{}, errors.New("no port list")
	}

	host, spec := dst[:i], dst[i+1:]

	ports, err := parsePorts(strings.Split(spec, ","), false)
	if err != nil {
		return target{}, err
	}

	t := target{ports: ports, text: host}

	switch {
	case strings.HasPrefix(host, tagPrefix):
		t.tag = strings.TrimPrefix(host, tagPrefix)
		if err := checkTagName(t.tag); err != nil {
			return target{}, err
		}
	case strings.Contains(host, "/"):
		p, err := parsePrefix(host)
		if err != nil {
			return target{}, err
		}

		t.prefix = p
	default:
		return target{}, fmt.Errorf("%q is neither a prefix nor a tag", host)
	}

	return t, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR: %w", s, err)
	}

	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped IPv6 prefix: spell it as IPv4", s)
	}

	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("%q is not canonical: it has host bits set (%s)", s, p.Masked())
	}

	return p, nil
}

func checkTagName(tag string) error {
	if tag == "" {
		return errors.New("empty tag")
	}

	if strings.HasPrefix(tag, tagPrefix) {
		return fmt.Errorf("tag %q carries the %q prefix: name it without", tag, tagPrefix)
	}

	if strings.ContainsAny(tag, ":,/") || strings.IndexFunc(tag, unicode.IsSpace) >= 0 {
		return fmt.Errorf("tag %q has a colon, comma, slash or whitespace in it", tag)
	}

	return nil
}

// parsePorts parses "*", "N" and "N-M" entries into one merged set. A
// repeated entry is an error when strict.
func parsePorts(spec []string, strict bool) (portSet, error) {
	var set portSet

	seen := map[string]bool{}

	for _, s := range spec {
		if strict && seen[s] {
			return nil, fmt.Errorf("port %q is listed twice", s)
		}

		seen[s] = true

		r, err := parsePortRange(s)
		if err != nil {
			return nil, err
		}

		set = append(set, r)
	}

	return set.merged(), nil
}

func parsePortRange(s string) (portRange, error) {
	if s == "*" {
		return portRange{portMin, portMax}, nil
	}

	loS, hiS, isRange := strings.Cut(s, "-")

	lo, err := parsePort(loS)
	if err != nil {
		return portRange{}, fmt.Errorf("port %q: %w", s, err)
	}

	hi := lo

	if isRange {
		if hi, err = parsePort(hiS); err != nil {
			return portRange{}, fmt.Errorf("port %q: %w", s, err)
		}

		if hi < lo {
			return portRange{}, fmt.Errorf("port range %q is reversed", s)
		}
	}

	return portRange{lo, hi}, nil
}

// parsePort accepts decimal digits only, so "+80", "-1" and " 80" are refused.
func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, errors.New("not a port number")
	}

	n, err := strconv.Atoi(s)
	if err != nil || n < portMin || n > portMax {
		return 0, fmt.Errorf("outside %d-%d", portMin, portMax)
	}

	return n, nil
}

// merged sorts the set and joins overlapping and adjacent ranges.
func (s portSet) merged() portSet {
	if len(s) == 0 {
		return nil
	}

	sorted := append(portSet(nil), s...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })

	out := portSet{sorted[0]}

	for _, r := range sorted[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi+1 {
			last.hi = max(last.hi, r.hi)

			continue
		}

		out = append(out, r)
	}

	return out
}

// covers reports whether every port of sub is in s; both are merged.
func (s portSet) covers(sub portSet) bool {
	for _, r := range sub {
		ok := false

		for _, o := range s {
			if o.lo <= r.lo && r.hi <= o.hi {
				ok = true

				break
			}
		}

		if !ok {
			return false
		}
	}

	return true
}

// holds reports whether the entry names the target's tag or contains its prefix.
func (e *entry) holds(t target) bool {
	if t.tag != "" {
		return e.tag == t.tag
	}

	return e.tag == "" && e.prefix.Bits() <= t.prefix.Bits() && e.prefix.Contains(t.prefix.Addr())
}

// admit returns "" when the entries admit the target, otherwise the reason,
// naming the nearest entry when there is one: the most specific entry that
// holds the target, else the first one that overlaps it.
func admit(entries []entry, t target) string {
	var (
		holders          portSet
		holder, overlaps *entry
	)

	for i := range entries {
		e := &entries[i]

		if !e.holds(t) {
			if overlaps == nil && t.tag == "" && e.tag == "" && e.prefix.Overlaps(t.prefix) {
				overlaps = e
			}

			continue
		}

		holders = append(holders, e.ports...)

		if holder == nil || e.prefix.Bits() > holder.prefix.Bits() {
			holder = e
		}
	}

	if holder == nil {
		if overlaps != nil {
			return fmt.Sprintf("nearest entry %s ports %s", overlaps.text, overlaps.spec)
		}

		return "no entry covers it"
	}

	if holders.merged().covers(t.ports) {
		return ""
	}

	return fmt.Sprintf("nearest entry %s ports %s", holder.text, holder.spec)
}
