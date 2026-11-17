// Package scan — secret and hygiene detection for repos.
package scan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Pattern is a secret signature.
type Pattern struct {
	Name string
	Re   *regexp.Regexp
	Sev  string // HIGH | MED
	Fix  string
}

var patterns = []Pattern{
	{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "HIGH", "Rotate the key in AWS IAM immediately, then remove from history."},
	{"Private key block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`), "HIGH", "Rotate it and remove from history with git filter-repo."},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "HIGH", "Revoke at api.slack.com, then purge from history."},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "HIGH", "Restrict/regenerate in Google Cloud console, then purge from history."},
	{"Stripe secret key", regexp.MustCompile(`sk_live_[A-Za-z0-9]{16,}`), "HIGH", "Rotate in Stripe dashboard, then purge from history."},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`), "HIGH", "Revoke at github.com/settings/tokens, then purge from history."},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "MED", "Usually a test artifact — confirm and remove."},
	{"Hardcoded credential", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["'][^"'\s]{8,}["']`), "MED", "Move to env vars or a secret manager. Verify it's not a real credential."},
}

// FileCheck flags suspicious tracked files by path.
type FileCheck struct {
	Match func(rel string) bool
	Sev   string
	Why   string
}

var fileChecks = []FileCheck{
	{func(rel string) bool { b := strings.ToLower(filepath.Base(rel)); return b == ".env" || strings.HasPrefix(b, ".env.") }, "HIGH", ".env file in git — likely contains real secrets"},
	{func(rel string) bool {
		b := strings.ToLower(rel)
		return strings.HasSuffix(b, ".pem") || strings.HasSuffix(b, ".key") ||
			strings.HasSuffix(b, ".pfx") || strings.HasSuffix(b, ".p12") ||
			strings.Contains(b, "id_rsa")
	}, "HIGH", "key material tracked in git"},
	{func(rel string) bool { return strings.Contains(rel, "node_modules/") }, "MED", "node_modules committed — 100MB of regret"},
	{func(rel string) bool { return strings.HasSuffix(rel, ".DS_Store") }, "LOW", "macOS junk file"},
	{func(rel string) bool {
		ext := strings.ToLower(filepath.Ext(rel))
		return ext == ".mp4" || ext == ".mov" || ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".iso" || ext == ".dmg"
	}, "LOW", "large binary tracked in git"},
}

// Finding is one problem discovered.
type Finding struct {
	Sev    string `json:"sev"`
	Type   string `json:"type"`
	Where  string `json:"where"`
	Sample string `json:"sample,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// HistoryHit is a secret that lives (or lived) anywhere in git history.
type HistoryHit struct {
	Type    string `json:"type"`
	Commits int    `json:"commits"`
	Example string `json:"example"`
}

// Mask shows enough to recognize, not enough to leak.
func Mask(s string) string {
	if len(s) > 10 {
		return s[:6] + "…" + s[len(s)-3:]
	}
	return s
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist": true, "build": true,
	".next": true, "__pycache__": true,
}

// ListFiles returns tracked + untracked (non-ignored) files, skip dirs filtered.
func ListFiles(root string) ([]string, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil, fmt.Errorf("not a git repository")
	}
	var out []string
	for _, args := range [][]string{{"ls-files"}, {"ls-files", "--others", "--exclude-standard"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		outBytes, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git failed: %v", err)
		}
		for _, f := range strings.Split(string(outBytes), "\n") {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			skip := false
			for _, part := range strings.Split(filepath.ToSlash(f), "/") {
				if skipDirs[part] {
					skip = true
					break
				}
			}
			if !skip {
				out = append(out, f)
			}
		}
	}
	return dedupe(out), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ScanFiles scans file contents and paths for findings.
func ScanFiles(root string, files []string) []Finding {
	var findings []Finding
	for _, rel := range files {
		for _, fc := range fileChecks {
			if fc.Match(rel) {
				findings = append(findings, Finding{Sev: fc.Sev, Type: fc.Why, Where: rel, Fix: suggestFor(fc.Why)})
			}
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		text := string(data)
		for _, p := range patterns {
			locs := p.Re.FindAllStringIndex(text, -1)
			for _, loc := range locs {
				line := 1 + strings.Count(text[:loc[0]], "\n")
				findings = append(findings, Finding{
					Sev: p.Sev, Type: p.Name,
					Where:  fmt.Sprintf("%s:%d", rel, line),
					Sample: Mask(text[loc[0]:loc[1]]),
					Fix:    p.Fix,
				})
			}
		}
	}
	return sortFindings(findings)
}

func suggestFor(why string) string {
	switch {
	case strings.Contains(why, ".env"):
		return "git rm --cached .env, add to .gitignore, rotate any keys inside it."
	case strings.Contains(why, "key material"):
		return "Remove and rotate. If it's a deploy key, generate a fresh one."
	case strings.Contains(why, "node_modules"):
		return "git rm -r --cached node_modules, add to .gitignore. The lockfile is enough."
	case strings.Contains(why, "junk"):
		return "Add .DS_Store to .gitignore and git rm --cached it."
	default:
		return "Add to .gitignore or use Git LFS for binaries."
	}
}

var sevOrder = map[string]int{"HIGH": 0, "MED": 1, "LOW": 2}

func sortFindings(f []Finding) []Finding {
	for i := 0; i < len(f); i++ {
		for j := i + 1; j < len(f); j++ {
			if sevOrder[f[j].Sev] < sevOrder[f[i].Sev] {
				f[i], f[j] = f[j], f[i]
			}
		}
	}
	return f
}

// ScanHistory sweeps all of git history with pickaxe (-G) for the
// high-signal secret patterns. Slow but thorough.
func ScanHistory(root string) []HistoryHit {
	highSignal := []struct {
		name, src string
	}{
		{"AWS Access Key ID", `AKIA[0-9A-Z]{16}`},
		{"Private key block", `-----BEGIN [A-Z ]*PRIVATE KEY`},
		{"Slack token", `xox[baprs]-[A-Za-z0-9-]{10,}`},
		{"GitHub token", `gh[pousr]_[A-Za-z0-9]{30,}`},
	}
	var hits []HistoryHit
	for _, p := range highSignal {
		cmd := exec.Command("git", "log", "--all", "--oneline", "-G"+p.src)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			continue // pattern absent → git exits empty
		}
		lines := nonEmpty(strings.Split(string(out), "\n"))
		if len(lines) > 0 {
			hits = append(hits, HistoryHit{Type: p.name + " (in git history)", Commits: len(lines), Example: lines[0]})
		}
	}
	return hits
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// HighCount counts HIGH severity findings + history hits.
func HighCount(findings []Finding, hits []HistoryHit) int {
	n := len(hits)
	for _, f := range findings {
		if f.Sev == "HIGH" {
			n++
		}
	}
	return n
}
