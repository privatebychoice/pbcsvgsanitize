# pbcsvgsanitize

A small, **security-first SVG sanitizer** for Go. It reduces an untrusted SVG to
a safe, **presentational-only** subset so it cannot execute script or contact a
third party — built for privacy-first, self-hosted sites.

It is **deny by default**: the input is parsed and only an explicit allowlist of
presentational elements and attributes is re-serialized. Everything else is
dropped.

## Why it exists

Go has no maintained, SVG-specific sanitizer, and general HTML sanitizers are the
wrong tool for standalone SVG — they parse with an HTML tokenizer that lowercases
camelCase attributes (`viewBox` → `viewbox`) and applies HTML foreign-content
rules. `pbcsvgsanitize` instead uses the standard library's **case-preserving**
XML decoder, so valid SVG survives while dangerous constructs are removed.

## Install

```bash
go get go.privatebychoice.com/pbcsvgsanitize
```

## Use

```go
import svgsanitize "go.privatebychoice.com/pbcsvgsanitize"

clean, res, err := svgsanitize.Sanitize(raw)
if err != nil {
    // Fail-closed: reject the asset. (Not an SVG, malformed, custom entities,
    // too large, too deep, or no <svg> root.)
    return err
}
_ = clean            // safe SVG bytes, ready to store/serve
if res.Removed() {
    // Optionally warn the author what was stripped.
    log.Printf("svg sanitized: removed elements=%v attributes=%v",
        res.RemovedElements, res.RemovedAttributes)
}
```

Options:

```go
svgsanitize.Sanitize(raw,
    svgsanitize.WithMaxBytes(1<<20), // cap input size (default 5 MiB)
    svgsanitize.WithMaxDepth(256),   // cap nesting  (default 512)
)
```

## What it removes

- `<script>` and all `on*` event handlers
- `<foreignObject>` and `<switch>` (embed arbitrary HTML)
- `<style>` elements and inline `style` attributes (CSS `url()` / `@import`)
- SMIL animation (`<animate>`, `<set>`, `animateTransform`, …)
- `<image>`, `<feImage>`, `<a>` (load/reference/navigate off-origin)
- `<metadata>` (privacy)
- DOCTYPE, processing instructions (e.g. `<?xml-stylesheet?>`), comments
- Elements/attributes in unknown namespaces (namespace injection)
- **Every external reference** — `href`/`xlink:href`, and `url(...)` funciris are
  permitted **only** as local `#id` fragment references. No off-origin loads.

The XML decoder does not resolve external entities or fetch external DTDs, so the
XXE / entity-expansion surface is closed; an SVG relying on custom entities fails
to parse (fail-closed) rather than being expanded.

## What it keeps

A conservative subset for icons, logos, and illustrations: containers (`g`,
`defs`, `symbol`, `use`, `title`, `desc`), shapes and paths, text, gradients and
patterns, clipping/masking/markers, and non-external filter primitives — with
their presentational and geometric attributes (values validated: no external
`url()`, no `javascript:`). See [`allowlist.go`](allowlist.go); it is deliberately
tight and easy to extend.

## Defense in depth (important)

Sanitization is **one** layer. Not every SVG vector can be filtered, so serve
untrusted SVGs in an **isolated context**: embed via `<img src>` (never inline
into the page DOM) under a restrictive Content-Security-Policy, and serve with
`Content-Type: image/svg+xml`. This is the OWASP "sanitize **and** isolate"
guidance.

## CLI

A small reference command lives in [`cmd/svgsanitize`](cmd/svgsanitize):

```bash
go run ./cmd/svgsanitize icon.svg              # sanitize a file to stdout
cat icon.svg | go run ./cmd/svgsanitize        # sanitize stdin
go run ./cmd/svgsanitize -report icon.svg      # also print what was removed
```

## Development

Common tasks live in the `Makefile` (requires Go 1.27+):

```bash
make check   # fmt-check + vet + test + govulncheck — run before pushing
make help    # list every target (race, cover, tidy, ...)
```

`make check` is the local quality gate. `govulncheck` runs via `go run` and is
never added to `go.mod`. GitHub Actions CI is planned separately.

## Testing

```bash
go test ./...
go test -run '^$' -fuzz=FuzzSanitize -fuzztime=30s   # fuzz the safety invariants
```

Tests use benign, **inline** fixtures (no standalone `.svg` files, no real hosts,
no working exploits) that assert dangerous constructs are stripped. The fuzz
target asserts the output is always well-formed XML and never contains
`<script>`, `javascript:`, `<foreignObject>`, or an injected HTML namespace.

## Design principles

- **Deny by default** — an allowlist of inert, presentational names; anything
  unrecognized is dropped.
- **No phone-home** — zero external references survive; no network access at
  runtime.
- **Fail-closed** — anything that can't be parsed safely is rejected, not
  guessed at.
- **Case-preserving** — stdlib XML, so `viewBox` and friends survive.
