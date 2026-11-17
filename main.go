// repo-sanitizer — find leaked secrets before someone else does. Go edition.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arch087146/repo-sanitizer/internal/scan"
	"github.com/Arch087146/repo-sanitizer/internal/ui"
)

const version = "1.0.0"

var valueFlags = map[string]bool{"--author": true, "--since": true, "--md": true, "--model": true, "--dir": true}

var positional []string

func extractPositionals() {
	args := os.Args[1:]
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			rest = append(rest, a)
			if valueFlags[a] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				rest = append(rest, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	os.Args = append([]string{os.Args[0]}, rest...)
}

func main() {
	extractPositionals()
	history := flag.Bool("history", false, "also sweep all of git history (slower)")
	jsonOut := flag.Bool("json", false, "machine-readable findings")
	flag.Usage = usage
	flag.Parse()

	root, _ := os.Getwd()
	if len(positional) > 0 {
		root = positional[0]
	}
	root, _ = filepath.Abs(root)

	files, err := scan.ListFiles(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}

	// interactive: no flags, real terminal
	if !*jsonOut && !*history && len(positional) == 0 && isTTY() {
		ui.Run(root, false)
		return
	}

	findings := scan.ScanFiles(root, files)
	var hits []scan.HistoryHit
	if *history {
		hits = scan.ScanHistory(root)
	}

	if *jsonOut {
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"filesScanned": len(files), "findings": findings, "historyHits": hits,
		})
	} else {
		fmt.Print(render(files, findings, hits))
	}

	if scan.HighCount(findings, hits) > 0 {
		os.Exit(1)
	}
}

func render(files []string, findings []scan.Finding, hits []scan.HistoryHit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n🧼 repo-sanitizer\nscanned %d tracked/untracked files\n\n", len(files))

	if len(findings) == 0 && len(hits) == 0 {
		b.WriteString("✔ Clean. No secrets, no junk. Your future self says thanks.\n\n")
		return b.String()
	}

	for _, f := range findings {
		tag := "[LOW ] "
		switch f.Sev {
		case "HIGH":
			tag = "[HIGH] "
		case "MED":
			tag = "[MED ] "
		}
		fmt.Fprintf(&b, "%s%s — %s\n", tag, f.Type, f.Where)
		if f.Sample != "" {
			fmt.Fprintf(&b, "        (%s)\n", f.Sample)
		}
		fmt.Fprintf(&b, "        fix: %s\n", f.Fix)
	}
	for _, h := range hits {
		fmt.Fprintf(&b, "[HIGH] %s\n        present in %d historical commit(s), e.g. %s\n", h.Type, h.Commits, h.Example)
		b.WriteString("        fix: deleting the file now does NOT remove it from history — use git filter-repo, then rotate every exposed key.\n")
	}

	high := scan.HighCount(findings, hits)
	if high > 0 {
		fmt.Fprintf(&b, "\n%d high-severity finding(s). Rotate keys FIRST, clean history SECOND.\n\n", high)
	} else {
		b.WriteString("\nNo high-severity findings. Mild embarrassment only.\n\n")
	}
	return b.String()
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func usage() {
	fmt.Print(`repo-sanitizer — find leaked secrets in your repo (Go edition)

Usage: repo-sanitizer [dir] [flags]

Run with no flags in a terminal → interactive TUI.

  --history         also sweep all of git history (slower)
  --json            machine-readable findings
  --help            this

Exit code 1 on any HIGH-severity finding — CI-friendly.
`)
}
