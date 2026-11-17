// Package ui — interactive Bubble Tea app for repo-sanitizer.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Arch087146/repo-sanitizer/internal/scan"
)

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
)

func paint(code, s string) string { return code + s + reset }

var banner = []string{
	"  ╔══╦ ╦╔╗╔╔═╗╦ ╦╔╦╗╦ ╦╔═╗╦═╗",
	"  ║ ║║ ║║║║╚═╗║ ║ ║ ║ ║║╣ ╠╦╝",
	"  ╚═╝╚═╝╝╚╝╚═╝╚═╝ ╩ ╚═╝╚═╝╩╚═",
}

const (
	stateSplash = iota
	stateMenu
	statePickRepo
	stateScanning
	stateResults
)

var scanMsgs = []string{
	"listing tracked files…",
	"grepping for tokens…",
	"hunting AWS keys…",
	"checking .env disasters…",
	"sniffing private keys…",
	"preparing the report…",
}

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type scanResult struct {
	findings []scan.Finding
	hits     []scan.HistoryHit
	nfiles   int
	err      error
}

type model struct {
	root     string
	history  bool
	state    int
	sel      int
	input    string
	frame    int
	msgIdx   int
	reveal   int
	full     string
	res      scanResult
	scanErr  string
	quitting bool
	splash   int
	saved    string
}

type tickMsg struct{}
type scanDoneMsg scanResult

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return tickMsg{} })
}

// Run launches the TUI (blocking).
func Run(root string, history bool) {
	m := model{root: root, history: history, state: stateSplash}
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		os.Exit(1)
	}
}

func (m model) Init() tea.Cmd { return tick(time.Millisecond * 90) }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}
		switch m.state {
		case stateSplash:
			m.state = stateMenu
		case stateMenu:
			switch msg.String() {
			case "up", "k":
				m.sel = (m.sel + 4) % 5
			case "down", "j":
				m.sel = (m.sel + 1) % 5
			case "enter":
				return m, m.choose()
			case "q", "esc":
				m.quitting = true
				return m, tea.Quit
			}
		case statePickRepo:
			switch msg.String() {
			case "enter":
				val := strings.TrimSpace(m.input)
				m.input = ""
				if val == "" {
					m.state = stateMenu
					return m, nil
				}
				root, _ := filepath.Abs(val)
				m.root = root
				return m, m.startScan()
			case "backspace":
				if len(m.input) > 0 {
					m.input = m.input[:len(m.input)-1]
				}
			case "esc":
				m.state = stateMenu
				m.input = ""
			default:
				if len(msg.String()) == 1 {
					m.input += msg.String()
				}
			}
		case stateResults:
			if m.reveal < len(m.full) {
				m.reveal = len(m.full)
				return m, tick(time.Millisecond * 60)
			}
			switch msg.String() {
			case "s":
				m.saveMD()
				return m, nil
			case "enter", "q", "esc":
				m.state = stateMenu
				m.sel, m.reveal, m.saved = 0, 0, ""
			}
		}
		return m, nil

	case tickMsg:
		var d time.Duration
		switch m.state {
		case stateSplash:
			m.splash++
			if m.splash >= len(banner)+2 {
				m.state = stateMenu
			}
			d = time.Millisecond * 90
		case stateScanning:
			m.frame++
			if m.frame%3 == 0 {
				m.msgIdx++
			}
			d = time.Millisecond * 90
		case stateResults:
			if m.reveal < len(m.full) {
				m.reveal += 4
				d = time.Millisecond * 10
			} else {
				d = time.Millisecond * 200
			}
		default:
			d = time.Millisecond * 200
		}
		return m, tick(d)

	case scanDoneMsg:
		r := scanResult(msg)
		if r.err != nil {
			m.scanErr = r.err.Error()
			m.state = stateMenu
			return m, nil
		}
		m.scanErr, m.saved = "", ""
		m.res = r
		m.state = stateResults
		m.reveal = 0
		m.full = m.buildFull()
		return m, tick(time.Millisecond * 10)
	}
	return m, nil
}

func (m *model) choose() tea.Cmd {
	switch m.sel {
	case 0:
		m.history = false
		return m.startScan()
	case 1:
		m.history = true
		return m.startScan()
	case 2:
		m.state = statePickRepo
		m.input = ""
	case 3, 4:
		m.quitting = true
		return tea.Quit
	}
	return nil
}

func (m *model) startScan() tea.Cmd {
	if _, err := os.Stat(filepath.Join(m.root, ".git")); err != nil {
		m.scanErr = fmt.Sprintf("%q is not a git repository", m.root)
		return nil
	}
	m.scanErr, m.saved = "", ""
	m.state = stateScanning
	m.frame, m.msgIdx = 0, 0
	withHistory := m.history
	root := m.root
	return tea.Batch(tick(time.Millisecond*90), func() tea.Msg {
		files, err := scan.ListFiles(root)
		if err != nil {
			return scanDoneMsg{err: err}
		}
		findings := scan.ScanFiles(root, files)
		var hits []scan.HistoryHit
		if withHistory {
			hits = scan.ScanHistory(root)
		}
		return scanDoneMsg{findings: findings, hits: hits, nfiles: len(files)}
	})
}

func (m *model) saveMD() {
	name := filepath.Base(m.root)
	file := filepath.Join(m.root, "SANITIZE.md")
	var b strings.Builder
	fmt.Fprintf(&b, "# 🧼 Sanitizer report for %q\n\n", name)
	fmt.Fprintf(&b, "> scanned %d files · %d findings · %d history hits\n\n", m.res.nfiles, len(m.res.findings), len(m.res.hits))
	for _, f := range m.res.findings {
		fmt.Fprintf(&b, "- **[%s]** %s — `%s`\n", f.Sev, f.Type, f.Where)
		if f.Sample != "" {
			fmt.Fprintf(&b, "  - sample: `%s`\n", f.Sample)
		}
	}
	for _, h := range m.res.hits {
		fmt.Fprintf(&b, "- **[HIGH]** %s — %d historical commit(s), e.g. `%s`\n", h.Type, h.Commits, h.Example)
	}
	b.WriteString("\n> Rotate keys FIRST, clean history SECOND.\n\n<sub>generated by repo-sanitizer (Go edition)</sub>\n")
	if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
		m.saved = "✗ " + err.Error()
	} else {
		m.saved = "✔ saved → " + file
	}
}

func (m *model) buildFull() string {
	var lines []string
	lines = append(lines, paint(dim, fmt.Sprintf("scanned %d tracked/untracked files", m.res.nfiles)), "")
	if len(m.res.findings) == 0 && len(m.res.hits) == 0 {
		lines = append(lines, paint(green, "✔ Clean. No secrets, no junk. Your future self says thanks."))
	}
	for _, f := range m.res.findings {
		tag := paint(dim, "[LOW ] ")
		switch f.Sev {
		case "HIGH":
			tag = paint(red, "[HIGH] ")
		case "MED":
			tag = paint(yellow, "[MED ] ")
		}
		lines = append(lines, tag+paint(bold, f.Type)+" — "+f.Where)
		if f.Sample != "" {
			lines = append(lines, "        "+paint(dim, "("+f.Sample+")"))
		}
		lines = append(lines, "        "+paint(dim, "fix: "+f.Fix))
	}
	for _, h := range m.res.hits {
		lines = append(lines,
			paint(red, "[HIGH] ")+paint(bold, h.Type),
			"        "+paint(dim, fmt.Sprintf("present in %d historical commit(s), e.g. %s", h.Commits, h.Example)),
			"        "+paint(dim, "fix: deleting the file now does NOT remove it from history — use git filter-repo, then rotate keys."))
	}
	high := scan.HighCount(m.res.findings, m.res.hits)
	lines = append(lines, "")
	if high > 0 {
		lines = append(lines, paint(bold+red, fmt.Sprintf("%d high-severity finding(s). Rotate keys FIRST, clean history SECOND.", high)))
	} else if len(m.res.findings) > 0 {
		lines = append(lines, paint(bold, "No high-severity findings. Mild embarrassment only."))
	}
	return strings.Join(lines, "\n")
}

func (m model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder

	switch m.state {
	case stateSplash:
		b.WriteString("\n\n")
		for i := 0; i < m.splash && i < len(banner); i++ {
			b.WriteString(paint(bold+magenta, banner[i]) + "\n")
		}
	case stateMenu:
		b.WriteString("\n")
		for _, l := range banner {
			b.WriteString(paint(bold+magenta, l) + "\n")
		}
		b.WriteString("\n  " + paint(dim, "find the secrets before someone else does") + "\n\n")
		items := []string{
			fmt.Sprintf("Scan current repo (%s)", filepath.Base(m.root)),
			"Scan with git history sweep (thorough, slower)",
			"Scan another repo",
			"Save report & exit",
			"Exit",
		}
		for i, it := range items {
			if i == m.sel {
				b.WriteString(paint(bold+cyan, "  ❯ ")+paint(bold, it)+"\n")
			} else {
				b.WriteString("    " + paint(dim, it) + "\n")
			}
		}
		if m.scanErr != "" {
			b.WriteString("\n  " + paint(red, "✗ "+m.scanErr) + "\n")
		}
		b.WriteString("\n  " + paint(dim, "↑/↓ select · Enter confirm · q quit") + "\n")
	case statePickRepo:
		b.WriteString("\n  path to repo:\n\n  ❯ " + m.input + "▌\n\n  " + paint(dim, "Enter confirm · Esc back") + "\n")
	case stateScanning:
		f := paint(cyan, frames[m.frame%len(frames)])
		b.WriteString("\n  " + f + " " + paint(dim, scanMsgs[m.msgIdx%len(scanMsgs)]) + "\n")
		if m.history {
			b.WriteString("\n  " + paint(dim, "(history sweep will take a moment longer)"))
		}
	case stateResults:
		b.WriteString("\n")
		b.WriteString(paint(bold+magenta, fmt.Sprintf("  🧼 SCANNING %q", filepath.Base(m.root))) + "\n\n")
		b.WriteString(m.full[:min(m.reveal, len(m.full))])
		if m.reveal >= len(m.full) {
			b.WriteString("\n\n  " + paint(dim, "s save SANITIZE.md · Enter menu · q quit"))
			if m.saved != "" {
				col := green
				if strings.HasPrefix(m.saved, "✗") {
					col = red
				}
				b.WriteString("\n  " + paint(col, m.saved))
			}
		}
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
