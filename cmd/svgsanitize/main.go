// Command svgsanitize sanitizes an SVG read from a file or stdin and writes the
// cleaned SVG to stdout. It is a small, known-good example of using the
// go.privatebychoice.com/pbcsvgsanitize library.
//
// Usage:
//
//	svgsanitize icon.svg                 # sanitize a file to stdout
//	cat icon.svg | svgsanitize           # sanitize stdin
//	svgsanitize -report icon.svg         # also print what was removed to stderr
//	svgsanitize -max-bytes 1048576 in.svg
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	svgsanitize "go.privatebychoice.com/pbcsvgsanitize"
)

func main() {
	report := flag.Bool("report", false, "print removed elements/attributes to stderr")
	maxBytes := flag.Int("max-bytes", 0, "maximum input size in bytes (0 = default)")
	maxDepth := flag.Int("max-depth", 0, "maximum element nesting depth (0 = default)")
	flag.Usage = usage
	flag.Parse()

	src, err := readInput(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "svgsanitize:", err)
		os.Exit(1)
	}

	var opts []svgsanitize.Option
	if *maxBytes > 0 {
		opts = append(opts, svgsanitize.WithMaxBytes(*maxBytes))
	}
	if *maxDepth > 0 {
		opts = append(opts, svgsanitize.WithMaxDepth(*maxDepth))
	}

	out, res, err := svgsanitize.Sanitize(src, opts...)
	if err != nil {
		// Fail-closed: rejected input produces no output and a non-zero exit.
		fmt.Fprintln(os.Stderr, "svgsanitize: rejected:", err)
		os.Exit(1)
	}

	if *report {
		if res.Removed() {
			if len(res.RemovedElements) > 0 {
				fmt.Fprintln(os.Stderr, "removed elements:", res.RemovedElements)
			}
			if len(res.RemovedAttributes) > 0 {
				fmt.Fprintln(os.Stderr, "removed attributes:", res.RemovedAttributes)
			}
		} else {
			fmt.Fprintln(os.Stderr, "nothing removed")
		}
	}

	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintln(os.Stderr, "svgsanitize:", err)
		os.Exit(1)
	}
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: svgsanitize [flags] [file]")
	fmt.Fprintln(os.Stderr, "       cat file.svg | svgsanitize [flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Sanitizes an SVG to a safe, presentational-only subset and writes it to stdout.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Flags:")
	flag.PrintDefaults()
}
