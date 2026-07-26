package svgsanitize

// This file defines the allowlist: the small set of presentational SVG elements
// and attributes that survive sanitization. It is deliberately conservative —
// deny by default. Anything not listed here is dropped. Extending it is a
// security decision: add only inert, presentational names whose values cannot
// reference an external resource or execute script.
//
// Intentionally excluded (and why):
//   - script, style                         → script execution / external CSS
//   - foreignObject, switch                 → embed arbitrary (X)HTML, incl. script
//   - a                                     → navigation (href), no value in an image
//   - image, feImage                        → reference/load external raster data
//   - animate, animateTransform, animateMotion, set, mpath (SMIL)
//                                           → can animate an attribute to an
//                                             external/javascript: value
//   - metadata                              → embedded metadata (privacy)
//   - use/href, gradient href, ...          → allowed as ELEMENTS, but their href
//                                             is restricted to local "#id" refs

// elementAllowed reports whether an element (by local name + namespace) is kept.
func elementAllowed(local, ns string) bool {
	return isSVGNS(ns) && allowedElements[local]
}

var allowedElements = map[string]bool{
	// Structure / containers.
	"svg": true, "g": true, "defs": true, "symbol": true, "use": true,
	"title": true, "desc": true,

	// Basic shapes & paths.
	"path": true, "rect": true, "circle": true, "ellipse": true,
	"line": true, "polyline": true, "polygon": true,

	// Text.
	"text": true, "tspan": true, "textPath": true,

	// Paint servers.
	"linearGradient": true, "radialGradient": true, "stop": true,
	"pattern": true,

	// Clipping / masking / markers.
	"clipPath": true, "mask": true, "marker": true,

	// Filters and their (non-external-referencing) primitives.
	"filter":              true,
	"feBlend":             true,
	"feColorMatrix":       true,
	"feComponentTransfer": true,
	"feFuncR":             true,
	"feFuncG":             true,
	"feFuncB":             true,
	"feFuncA":             true,
	"feComposite":         true,
	"feConvolveMatrix":    true,
	"feDiffuseLighting":   true,
	"feDisplacementMap":   true,
	"feDistantLight":      true,
	"feDropShadow":        true,
	"feFlood":             true,
	"feGaussianBlur":      true,
	"feMerge":             true,
	"feMergeNode":         true,
	"feMorphology":        true,
	"feOffset":            true,
	"fePointLight":        true,
	"feSpecularLighting":  true,
	"feSpotLight":         true,
	"feTile":              true,
	"feTurbulence":        true,
}

// globalAttrs is the set of safe, presentational/geometric attributes permitted
// on any allowed element. href, style, on* and namespace-scoped attributes are
// handled separately in filterAttr / filterPlainAttr, not here. Every value is
// still run through safeValue (no external url(), no javascript:).
var globalAttrs = map[string]bool{
	// Identity / structure.
	"id": true, "class": true, "role": true, "lang": true,

	// Geometry & coordinates.
	"x": true, "y": true, "x1": true, "y1": true, "x2": true, "y2": true,
	"cx": true, "cy": true, "r": true, "rx": true, "ry": true,
	"fx": true, "fy": true, "fr": true,
	"width": true, "height": true, "d": true, "points": true,
	"dx": true, "dy": true, "rotate": true,
	"transform": true, "gradientTransform": true, "patternTransform": true,
	"viewBox": true, "preserveAspectRatio": true,
	"gradientUnits": true, "spreadMethod": true, "offset": true,
	"patternUnits": true, "patternContentUnits": true,
	"markerWidth": true, "markerHeight": true, "markerUnits": true,
	"refX": true, "refY": true, "orient": true,
	"clipPathUnits": true, "maskUnits": true, "maskContentUnits": true,
	"primitiveUnits": true, "filterUnits": true,
	"startOffset": true, "textLength": true, "lengthAdjust": true,
	"pathLength": true, "side": true,

	// Presentation.
	"fill": true, "fill-opacity": true, "fill-rule": true,
	"stroke": true, "stroke-width": true, "stroke-linecap": true,
	"stroke-linejoin": true, "stroke-miterlimit": true,
	"stroke-dasharray": true, "stroke-dashoffset": true, "stroke-opacity": true,
	"opacity": true, "color": true, "stop-color": true, "stop-opacity": true,
	"visibility": true, "display": true, "overflow": true,
	"vector-effect": true, "paint-order": true, "shape-rendering": true,
	"color-interpolation": true, "color-interpolation-filters": true,
	"clip-path": true, "clip-rule": true, "mask": true, "filter": true,
	"marker-start": true, "marker-mid": true, "marker-end": true,
	"mix-blend-mode": true, "isolation": true,

	// Text presentation.
	"font-family": true, "font-size": true, "font-size-adjust": true,
	"font-style": true, "font-weight": true, "font-variant": true,
	"font-stretch": true, "text-anchor": true, "letter-spacing": true,
	"word-spacing": true, "text-decoration": true, "dominant-baseline": true,
	"alignment-baseline": true, "baseline-shift": true, "writing-mode": true,
	"direction": true, "unicode-bidi": true, "white-space": true,

	// Filter-primitive attributes (values are numbers/keywords/local refs).
	"in": true, "in2": true, "result": true, "stdDeviation": true,
	"mode": true, "values": true, "type": true, "tableValues": true,
	"slope": true, "intercept": true, "amplitude": true, "exponent": true,
	"k1": true, "k2": true, "k3": true, "k4": true, "operator": true,
	"radius": true, "scale": true,
	"xChannelSelector": true, "yChannelSelector": true,
	"order": true, "kernelMatrix": true, "divisor": true, "bias": true,
	"targetX": true, "targetY": true, "edgeMode": true, "preserveAlpha": true,
	"surfaceScale": true, "diffuseConstant": true, "specularConstant": true,
	"specularExponent": true, "azimuth": true, "elevation": true,
	"pointsAtX": true, "pointsAtY": true, "pointsAtZ": true,
	"limitingConeAngle": true, "baseFrequency": true, "numOctaves": true,
	"seed": true, "stitchTiles": true, "kernelUnitLength": true,
	"flood-color": true, "flood-opacity": true, "lighting-color": true,
}
