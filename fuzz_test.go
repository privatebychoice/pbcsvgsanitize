package svgsanitize

import (
	"strings"
	"testing"
)

// FuzzSanitize asserts the sanitizer's safety invariants hold for arbitrary
// input: it never panics, and any successful output is well-formed XML that
// contains none of the dangerous constructs the allowlist forbids.
func FuzzSanitize(f *testing.F) {
	seeds := []string{
		svgOpen + `<path d="M0 0h1v1H0z" fill="#000"/></svg>`,
		svgOpen + `<script>alert(1)</script></svg>`,
		svgOpen + `<rect onload="x" width="1" height="1"/></svg>`,
		svgOpen + `<use xlink:href="https://evil.example/#a"/></svg>`,
		svgOpen + `<foreignObject><b/></foreignObject></svg>`,
		`<?xml-stylesheet href="https://evil.example/x.css"?>` + svgOpen + `</svg>`,
		`<!DOCTYPE svg [ <!ENTITY x "y"> ]>` + svgOpen + `<title>&x;</title></svg>`,
		`<div/>`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		out, res, err := Sanitize(in)
		if err != nil {
			return // fail-closed rejection is a valid outcome
		}
		if out == nil || res == nil {
			t.Fatalf("nil output/result with nil error")
		}
		if err := reparse(out); err != nil {
			t.Fatalf("sanitized output is not well-formed XML: %v\ninput=%q\noutput=%q", err, in, out)
		}
		low := strings.ToLower(string(out))
		for _, forbidden := range []string{"<script", "</script", "javascript:", "<foreignobject", "<iframe", "xmlns=\"http://www.w3.org/1999/xhtml"} {
			if strings.Contains(low, forbidden) {
				t.Fatalf("sanitized output contains forbidden %q\ninput=%q\noutput=%q", forbidden, in, out)
			}
		}
	})
}
