package svgsanitize

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// NOTE ON TEST FIXTURES: these are benign, inline test strings, not real
// malware. They contain the *patterns* a sanitizer must strip (a <script> tag,
// an onload= attribute, an external href) purely to assert removal. There are no
// standalone .svg files in this repo, no working exploits, and no real hosts —
// only RFC-reserved placeholders like "evil.example". A <script> in a Go test
// string is inert; the test proves it is gone from the output.

const svgOpen = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">`

func TestSanitize_Transform(t *testing.T) {
	tests := []struct {
		name            string
		in              string
		wantContains    []string
		wantOmits       []string
		wantRemovedEl   []string
		wantRemovedAttr []string
	}{
		{
			name:         "clean icon passes, camelCase preserved",
			in:           svgOpen + `<path d="M0 0h10v10H0z" fill="#123456"/></svg>`,
			wantContains: []string{`<path`, `d="M0 0h10v10H0z"`, `fill="#123456"`},
		},
		{
			name:          "viewBox and gradient camelCase survive",
			in:            `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><linearGradient gradientTransform="rotate(90)"><stop offset="0" stop-color="#fff"/></linearGradient></svg>`,
			wantContains:  []string{`viewBox="0 0 24 24"`, `<linearGradient`, `gradientTransform="rotate(90)"`, `stop-color="#fff"`},
			wantRemovedEl: nil,
		},
		{
			name:          "script element is stripped with its subtree",
			in:            svgOpen + `<script>alert(1)</script><rect width="1" height="1"/></svg>`,
			wantOmits:     []string{"<script", "alert"},
			wantContains:  []string{`<rect`},
			wantRemovedEl: []string{"script"},
		},
		{
			name:            "onload event handler is stripped",
			in:              svgOpen + `<rect width="1" height="1" onload="alert(1)"/></svg>`,
			wantOmits:       []string{"onload", "alert"},
			wantContains:    []string{`<rect`, `width="1"`},
			wantRemovedAttr: []string{"onload"},
		},
		{
			name:          "foreignObject is stripped",
			in:            svgOpen + `<foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>x</script></body></foreignObject><rect width="1" height="1"/></svg>`,
			wantOmits:     []string{"foreignObject", "<script", "<body"},
			wantContains:  []string{"<rect"},
			wantRemovedEl: []string{"foreignObject"},
		},
		{
			name:          "image element is stripped",
			in:            svgOpen + `<image href="https://evil.example/x.png"/><rect width="1" height="1"/></svg>`,
			wantOmits:     []string{"<image", "evil.example"},
			wantRemovedEl: []string{"image"},
		},
		{
			name:          "anchor element is stripped",
			in:            svgOpen + `<a href="https://evil.example/"><rect width="1" height="1"/></a></svg>`,
			wantOmits:     []string{"<a ", "evil.example"},
			wantRemovedEl: []string{"a"},
		},
		{
			name:          "style element is stripped",
			in:            svgOpen + `<style>@import url(https://evil.example/x.css);</style><rect width="1" height="1"/></svg>`,
			wantOmits:     []string{"<style", "@import", "evil.example"},
			wantRemovedEl: []string{"style"},
		},
		{
			name:          "SMIL animate element is stripped",
			in:            svgOpen + `<rect width="1" height="1"><animate attributeName="href" to="javascript:alert(1)"/></rect></svg>`,
			wantOmits:     []string{"<animate", "javascript:"},
			wantContains:  []string{"<rect"},
			wantRemovedEl: []string{"animate"},
		},
		{
			name:            "inline style attribute is stripped",
			in:              svgOpen + `<rect width="1" height="1" style="fill:url(https://evil.example/x)"/></svg>`,
			wantOmits:       []string{"style=", "evil.example"},
			wantRemovedAttr: []string{"style"},
		},
		{
			name:            "javascript: in href is stripped",
			in:              svgOpen + `<use href="javascript:alert(1)"/></svg>`,
			wantOmits:       []string{"javascript:", "alert"},
			wantContains:    []string{"<use"},
			wantRemovedAttr: []string{"href"},
		},
		{
			name:            "data: URI in href is stripped",
			in:              svgOpen + `<use href="data:image/svg+xml,%3Csvg%3E"/></svg>`,
			wantOmits:       []string{"data:"},
			wantRemovedAttr: []string{"href"},
		},
		{
			name:            "external xlink:href is stripped, element kept",
			in:              svgOpen + `<use xlink:href="https://evil.example/x#a"/></svg>`,
			wantOmits:       []string{"evil.example"},
			wantContains:    []string{"<use"},
			wantRemovedAttr: []string{"xlink:href"},
		},
		{
			name:         "local xlink:href is kept",
			in:           svgOpen + `<defs><rect id="a" width="1" height="1"/></defs><use xlink:href="#a"/></svg>`,
			wantContains: []string{`xlink:href="#a"`},
		},
		{
			name:            "external url() in presentation attr is stripped",
			in:              svgOpen + `<rect width="1" height="1" filter="url(https://evil.example/x#f)"/></svg>`,
			wantOmits:       []string{"evil.example"},
			wantContains:    []string{"<rect"},
			wantRemovedAttr: []string{"filter"},
		},
		{
			name:         "local url() in presentation attr is kept",
			in:           svgOpen + `<rect width="1" height="1" fill="url(#grad)"/></svg>`,
			wantContains: []string{`fill="url(#grad)"`},
		},
		{
			name:         "currentColor keyword is kept",
			in:           svgOpen + `<path d="M0 0" fill="currentColor"/></svg>`,
			wantContains: []string{`fill="currentColor"`},
		},
		{
			name:         "foreign-namespace element (namespace injection) is stripped",
			in:           svgOpen + `<g><x:evil xmlns:x="http://evil.example/ns"><script/></x:evil></g></svg>`,
			wantOmits:    []string{"evil", "<script"},
			wantContains: []string{"<g>"},
		},
		{
			name:         "processing instruction (xml-stylesheet) is dropped",
			in:           `<?xml-stylesheet type="text/css" href="https://evil.example/x.css"?>` + svgOpen + `<rect width="1" height="1"/></svg>`,
			wantOmits:    []string{"xml-stylesheet", "evil.example"},
			wantContains: []string{"<rect"},
		},
		{
			name:         "comment is dropped",
			in:           svgOpen + `<!-- secret --><rect width="1" height="1"/></svg>`,
			wantOmits:    []string{"secret", "<!--"},
			wantContains: []string{"<rect"},
		},
		{
			name:         "nested svg viewport is allowed",
			in:           svgOpen + `<svg viewBox="0 0 2 2"><rect width="1" height="1"/></svg></svg>`,
			wantContains: []string{`viewBox="0 0 2 2"`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, res, err := Sanitize([]byte(tc.in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := string(out)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("output missing %q\n--- output ---\n%s", want, got)
				}
			}
			for _, bad := range tc.wantOmits {
				if strings.Contains(got, bad) {
					t.Errorf("output should not contain %q\n--- output ---\n%s", bad, got)
				}
			}
			for _, want := range tc.wantRemovedEl {
				if !contains(res.RemovedElements, want) {
					t.Errorf("RemovedElements %v missing %q", res.RemovedElements, want)
				}
			}
			for _, want := range tc.wantRemovedAttr {
				if !contains(res.RemovedAttributes, want) {
					t.Errorf("RemovedAttributes %v missing %q", res.RemovedAttributes, want)
				}
			}
			// The output must always be well-formed XML.
			if err := reparse(out); err != nil {
				t.Errorf("output is not well-formed XML: %v\n--- output ---\n%s", err, got)
			}
		})
	}
}

func TestSanitize_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		opts []Option
	}{
		{name: "empty input", in: ""},
		{name: "not an svg root", in: `<html xmlns="http://www.w3.org/1999/xhtml"><body/></html>`},
		{name: "bare non-svg root", in: `<div/>`},
		{name: "malformed xml", in: svgOpen + `<rect></svg>`},
		{
			name: "custom internal entity (billion-laughs class) fails closed",
			in:   `<!DOCTYPE svg [ <!ENTITY x "boom"> ]>` + svgOpen + `<title>&x;</title></svg>`,
		},
		{
			name: "external entity (XXE) fails closed",
			in:   `<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` + svgOpen + `<title>&xxe;</title></svg>`,
		},
		{
			name: "depth limit exceeded",
			in:   svgOpen + `<g><g><rect width="1" height="1"/></g></g></svg>`,
			opts: []Option{WithMaxDepth(2)},
		},
		{
			name: "byte limit exceeded",
			in:   svgOpen + `<rect width="1" height="1"/></svg>`,
			opts: []Option{WithMaxBytes(10)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := Sanitize([]byte(tc.in), tc.opts...)
			if err == nil {
				t.Fatalf("expected an error, got none\n--- output ---\n%s", out)
			}
			if out != nil {
				t.Errorf("expected nil output on error, got %q", out)
			}
		})
	}
}

func TestSanitize_ResultRemovedReport(t *testing.T) {
	out, res, err := Sanitize([]byte(svgOpen + `<rect width="1" height="1"/></svg>`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed() {
		t.Errorf("clean input should report nothing removed, got %+v", res)
	}
	if !strings.Contains(string(out), "<rect") {
		t.Errorf("expected <rect> in output: %s", out)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// reparse confirms the sanitized output is well-formed XML.
func reparse(b []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
