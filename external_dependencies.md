# External Dependencies

The sanitizer core is **pure Go standard library** — **zero third-party
dependencies** — and makes **no network calls at runtime**. Sanitization is done
with `encoding/xml`; nothing is fetched, and no external entities or DTDs are
resolved.

| Name | Version | Project URL | Purpose | Security / privacy notes |
|------|---------|-------------|---------|--------------------------|
| _(none)_ | — | — | — | The sanitizer and CLI use only the Go standard library. |

## Considered and rejected: rasterize-to-PNG fallback

A rasterize-to-PNG fallback (flattening an unsanitizable SVG into a raster image)
was considered and **deliberately dropped**. The candidate pure-Go rasterizers
(e.g. `srwiley/oksvg` + `srwiley/rasterx`) have open security issues on their
trackers, and pulling them in to sidestep an already-rejected input is not worth
the added attack surface and transitive-dependency risk.

**Behavior instead:** an SVG that cannot be sanitized safely is **rejected**
(fail-closed). Do not re-introduce a rasterizer dependency without a fresh
security review.
