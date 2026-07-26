// Package svgsanitize is a small, security-first SVG sanitizer.
//
// It parses an SVG with the standard library's *case-preserving* XML decoder
// (so camelCase attributes like viewBox survive) and re-serializes only an
// explicit allowlist of presentational elements and attributes — deny by
// default. Everything not on the allowlist is dropped: <script>, all on*
// event handlers, <foreignObject>, <style>, SMIL animation, <image>/<a>,
// DOCTYPE / processing instructions / comments, unknown namespaces, embedded
// metadata, and — critically — *every* external reference (only local "#id"
// fragment references are permitted). A sanitized SVG therefore cannot execute
// script or contact a third party.
//
// The parser does not resolve external entities or fetch external DTDs, so the
// XXE / external-entity surface is closed; an SVG that relies on custom entities
// fails to parse (fail-closed) rather than being silently expanded.
//
// This is one layer of defense. Callers should still serve untrusted SVGs in an
// isolated context (e.g. via <img src> under a restrictive CSP, never inlined
// into the page DOM), per OWASP guidance — not every SVG vector can be filtered.
package svgsanitize

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// XML namespaces we understand. Anything else is treated as foreign and dropped.
const (
	nsSVG   = "http://www.w3.org/2000/svg"
	nsXLink = "http://www.w3.org/1999/xlink"
	nsXML   = "http://www.w3.org/XML/1998/namespace"
)

// Defaults for the resource limits (guard against oversized / deeply-nested
// inputs). Overridable via options.
const (
	defaultMaxBytes = 5 << 20 // 5 MiB
	defaultMaxDepth = 512
)

type config struct {
	maxBytes int
	maxDepth int
}

// Option configures a Sanitizer.
type Option func(*config)

// WithMaxBytes caps the accepted input size in bytes. A non-positive value is
// ignored (the default is kept).
func WithMaxBytes(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxBytes = n
		}
	}
}

// WithMaxDepth caps the element nesting depth. A non-positive value is ignored.
func WithMaxDepth(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxDepth = n
		}
	}
}

// Sanitizer sanitizes SVG documents against a fixed allowlist. It holds no
// mutable state and is safe for concurrent use.
type Sanitizer struct {
	cfg config
}

// New builds a Sanitizer with the given options.
func New(opts ...Option) *Sanitizer {
	c := config{maxBytes: defaultMaxBytes, maxDepth: defaultMaxDepth}
	for _, o := range opts {
		o(&c)
	}
	return &Sanitizer{cfg: c}
}

// Result reports what the sanitizer removed, so a caller can warn the author.
// Both slices are sorted and de-duplicated. An empty Result means nothing was
// stripped (the input was already within the allowlist).
type Result struct {
	// RemovedElements are the names of elements that were dropped (with their
	// entire subtree), e.g. "script", "foreignObject".
	RemovedElements []string
	// RemovedAttributes are the names of attributes that were dropped, e.g.
	// "onload", "xlink:href", "style".
	RemovedAttributes []string
}

// Removed reports whether anything was stripped.
func (r *Result) Removed() bool {
	return len(r.RemovedElements) > 0 || len(r.RemovedAttributes) > 0
}

// Sanitize is a convenience wrapper around New(opts...).Sanitize.
func Sanitize(src []byte, opts ...Option) ([]byte, *Result, error) {
	return New(opts...).Sanitize(src)
}

// Sanitize parses src and returns a cleaned SVG plus a Result describing what
// was removed. It returns an error (and no output) only when the input cannot
// be handled safely at all: empty, too large, not well-formed XML, not rooted
// at <svg>, exceeds the depth limit, or relies on custom/undefined entities.
// Dropping disallowed elements/attributes is normal and is reported in Result,
// not treated as an error — callers decide whether any removal warrants a
// warning. The design is fail-closed: on error, reject the asset.
func (s *Sanitizer) Sanitize(src []byte) ([]byte, *Result, error) {
	if len(src) == 0 {
		return nil, nil, errors.New("svgsanitize: empty input")
	}
	if len(src) > s.cfg.maxBytes {
		return nil, nil, fmt.Errorf("svgsanitize: input of %d bytes exceeds limit of %d", len(src), s.cfg.maxBytes)
	}

	dec := xml.NewDecoder(bytes.NewReader(src))
	dec.Strict = true
	// Leave dec.Entity nil: only the five predefined XML entities are known, and
	// any custom/undefined entity is a hard parse error. This closes the
	// billion-laughs / external-entity surface (encoding/xml never fetches
	// external DTDs).

	var out bytes.Buffer
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")

	removedEl := map[string]bool{}
	removedAttr := map[string]bool{}

	depth := 0     // nesting of emitted (kept) elements; 1 at the root
	skipDepth := 0 // >0 while inside a dropped subtree
	sawRoot := false
	rootDone := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("svgsanitize: parse: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if skipDepth > 0 { // already inside a dropped subtree
				skipDepth++
				continue
			}
			local := t.Name.Local
			ns := t.Name.Space

			if !sawRoot {
				if !(local == "svg" && isSVGNS(ns)) {
					return nil, nil, errors.New("svgsanitize: root element is not <svg>")
				}
				sawRoot = true
				depth = 1
				out.WriteString("<svg")
				out.WriteString(` xmlns="` + nsSVG + `" xmlns:xlink="` + nsXLink + `"`)
				writeAttrs(&out, t.Attr, removedAttr)
				out.WriteByte('>')
				continue
			}

			if depth+1 > s.cfg.maxDepth {
				return nil, nil, fmt.Errorf("svgsanitize: nesting exceeds limit of %d", s.cfg.maxDepth)
			}
			if !elementAllowed(local, ns) {
				removedEl[nameLabel(t.Name)] = true
				skipDepth = 1
				continue
			}
			out.WriteByte('<')
			out.WriteString(local)
			writeAttrs(&out, t.Attr, removedAttr)
			out.WriteByte('>')
			depth++

		case xml.EndElement:
			if skipDepth > 0 {
				skipDepth--
				continue
			}
			if !sawRoot || rootDone {
				continue
			}
			out.WriteString("</")
			out.WriteString(t.Name.Local)
			out.WriteByte('>')
			depth--
			if depth == 0 {
				rootDone = true
			}

		case xml.CharData:
			if skipDepth > 0 || !sawRoot || rootDone {
				continue
			}
			_ = xml.EscapeText(&out, t)

		case xml.Comment, xml.Directive, xml.ProcInst:
			// Dropped entirely: comments, DOCTYPE (Directive), and processing
			// instructions such as <?xml-stylesheet?> (an external-resource vector).
			continue
		}
	}

	if !sawRoot {
		return nil, nil, errors.New("svgsanitize: no <svg> root element found")
	}

	return out.Bytes(), &Result{
		RemovedElements:   sortedKeys(removedEl),
		RemovedAttributes: sortedKeys(removedAttr),
	}, nil
}

// writeAttrs writes the allowlisted, value-validated attributes of an element,
// recording any it drops in removed.
func writeAttrs(out *bytes.Buffer, attrs []xml.Attr, removed map[string]bool) {
	for _, a := range attrs {
		name, value, ok := filterAttr(a)
		if !ok {
			if !isNamespaceDecl(a) { // xmlns declarations are re-emitted canonically, not "removed"
				removed[nameLabel(a.Name)] = true
			}
			continue
		}
		out.WriteByte(' ')
		out.WriteString(name)
		out.WriteString(`="`)
		_ = xml.EscapeText(out, []byte(value))
		out.WriteByte('"')
	}
}

// filterAttr decides whether an attribute survives. It returns the output name
// (with a canonical prefix where relevant) and the value, or ok=false to drop.
func filterAttr(a xml.Attr) (name, value string, ok bool) {
	if isNamespaceDecl(a) {
		return "", "", false // xmlns / xmlns:* handled canonically on the root
	}
	local := a.Name.Local
	ns := a.Name.Space

	switch ns {
	case nsXLink:
		if local == "href" {
			if h, ok := safeLocalRef(a.Value); ok {
				return "xlink:href", h, true
			}
		}
		return "", "", false
	case nsXML:
		if local == "lang" || local == "space" {
			return "xml:" + local, a.Value, true
		}
		return "", "", false
	case "", nsSVG:
		return filterPlainAttr(local, a.Value)
	default:
		return "", "", false // foreign namespace
	}
}

// filterPlainAttr handles attributes in the SVG (or empty) namespace.
func filterPlainAttr(local, value string) (name, out string, ok bool) {
	l := strings.ToLower(local)
	switch {
	case l == "href":
		if h, ok := safeLocalRef(value); ok {
			return "href", h, true
		}
		return "", "", false
	case strings.HasPrefix(l, "on"): // event handlers: onload, onclick, ...
		return "", "", false
	case local == "style": // inline CSS can carry url()/expressions; dropped
		return "", "", false
	case strings.HasPrefix(l, "aria-"):
		if safeValue(value) {
			return local, value, true
		}
		return "", "", false
	case globalAttrs[local]:
		if safeValue(value) {
			return local, value, true
		}
		return "", "", false
	default:
		return "", "", false
	}
}

// safeLocalRef accepts only a local fragment reference ("#id"); everything else
// (http(s):, //, data:, javascript:, relative paths, ...) is rejected so a
// sanitized SVG never dereferences an external resource.
func safeLocalRef(v string) (string, bool) {
	h := strings.TrimSpace(v)
	if h == "" || !strings.HasPrefix(h, "#") {
		return "", false
	}
	if strings.ContainsAny(h, " \t\r\n") {
		return "", false
	}
	return h, true
}

// safeValue rejects attribute values that would reach off-origin or execute:
// a javascript: scheme, or a url(...) funciri whose target is not a local "#id".
func safeValue(v string) bool {
	lv := strings.ToLower(v)
	if strings.Contains(lv, "javascript:") {
		return false
	}
	if strings.Contains(lv, "url(") && hasNonLocalURL(lv) {
		return false
	}
	return true
}

// hasNonLocalURL scans an already-lower-cased value for url(...) targets that
// are not local "#id" fragment references.
func hasNonLocalURL(lower string) bool {
	s := lower
	for {
		i := strings.Index(s, "url(")
		if i < 0 {
			return false
		}
		rest := s[i+len("url("):]
		j := strings.IndexByte(rest, ')')
		if j < 0 {
			return true // malformed url( — treat as unsafe
		}
		arg := strings.TrimSpace(rest[:j])
		arg = strings.Trim(arg, `"'`)
		arg = strings.TrimSpace(arg)
		if !strings.HasPrefix(arg, "#") {
			return true
		}
		s = rest[j+1:]
	}
}

// isNamespaceDecl reports whether an attribute is an xmlns / xmlns:prefix
// declaration (which we re-emit canonically on the root rather than copy).
func isNamespaceDecl(a xml.Attr) bool {
	return a.Name.Local == "xmlns" || a.Name.Space == "xmlns"
}

func isSVGNS(ns string) bool { return ns == nsSVG || ns == "" }

// nameLabel renders an xml.Name for the removal report.
func nameLabel(n xml.Name) string {
	switch n.Space {
	case "", nsSVG:
		return n.Local
	case nsXLink:
		return "xlink:" + n.Local
	case nsXML:
		return "xml:" + n.Local
	default:
		return "{" + n.Space + "}" + n.Local
	}
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
