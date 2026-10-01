package main

import (
	"fmt"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type level int

const (
	neutral level = iota
	debug
	info
	warn
	errorLevel
)

type model struct {
	name      string
	raw       []string
	safe      []string
	levels    []level
	enabled   [5]bool
	sanitized bool
	searching bool
	query     string
	top       int
	xoff      int
	width     int
	height    int
	rows      []int
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("24")).Padding(0, 1)
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("221"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	debugStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("246"))
	searchStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("60")).Padding(0, 1)
)

func newModel(name, raw, safe string) model {
	rawLines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	safeLines := strings.Split(strings.TrimSuffix(safe, "\n"), "\n")
	m := model{
		name: name, raw: rawLines, safe: safeLines, levels: classify(rawLines),
		enabled: [5]bool{true, true, true, true, true}, sanitized: true,
	}
	m.rebuildRows()
	return m
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clamp()
		return m, nil
	case tea.KeyMsg:
		if m.searching {
			switch msg.String() {
			case "enter", "esc":
				m.searching = false
			case "backspace":
				if len(m.query) > 0 {
					_, size := utf8.DecodeLastRuneInString(m.query)
					m.query = m.query[:len(m.query)-size]
				}
			default:
				if msg.Type == tea.KeyRunes {
					m.query += string(msg.Runes)
				}
			}
			m.top = 0
			m.rebuildRows()
			m.clamp()
			return m, nil
		}

		rebuild := false
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "/":
			m.searching = true
		case "c":
			m.query, m.top = "", 0
			rebuild = true
		case "r", "tab":
			m.sanitized = !m.sanitized
			m.top = 0
			rebuild = true
		case "e":
			m.enabled = [5]bool{false, false, false, false, true}
			m.top = 0
			rebuild = true
		case "x":
			m.enabled[errorLevel] = !m.enabled[errorLevel]
			m.top = 0
			rebuild = true
		case "w":
			m.enabled[warn] = !m.enabled[warn]
			m.top = 0
			rebuild = true
		case "i":
			m.enabled[info] = !m.enabled[info]
			m.top = 0
			rebuild = true
		case "d":
			m.enabled[debug] = !m.enabled[debug]
			m.top = 0
			rebuild = true
		case "n":
			m.enabled[neutral] = !m.enabled[neutral]
			m.top = 0
			rebuild = true
		case "a":
			m.enabled = [5]bool{true, true, true, true, true}
			m.top = 0
			rebuild = true
		case "up", "k":
			m.top--
		case "down", "j":
			m.top++
		case "pgup":
			m.top -= m.pageHeight()
		case "pgdown", " ":
			m.top += m.pageHeight()
		case "home", "g":
			m.top = 0
		case "end", "G":
			m.top = len(m.visible())
		case "left", "h":
			m.xoff -= 8
		case "right", "l":
			m.xoff += 8
		}
		if rebuild {
			m.rebuildRows()
		}
		m.clamp()
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}
	mode := "SANITIZED"
	if !m.sanitized {
		mode = "RAW / PRIVATE"
	}
	visible := m.visible()
	header := headerStyle.Width(max(0, m.width-2)).Render(fmt.Sprintf("CLAIRE  %s  %s  %d/%d lines", mode, m.name, len(visible), len(m.raw)))
	filters := fmt.Sprintf("%s  %s  %s  %s  %s", statusFlag("ERR", m.enabled[errorLevel]), statusFlag("WARN", m.enabled[warn]), statusFlag("INFO", m.enabled[info]), statusFlag("DEBUG", m.enabled[debug]), statusFlag("OTHER", m.enabled[neutral]))
	if m.query != "" {
		filters += "  /" + m.query
	}
	rows := []string{header, dimStyle.Render(filters)}
	end := min(len(visible), m.top+m.pageHeight())
	lines := m.safe
	if !m.sanitized {
		lines = m.raw
	}
	for _, index := range visible[m.top:end] {
		text := fmt.Sprintf("%6d  %s", index+1, lines[index])
		text = crop(text, m.xoff, m.width)
		switch m.levels[index] {
		case errorLevel:
			text = errorStyle.Render(text)
		case warn:
			text = warnStyle.Render(text)
		case info:
			text = infoStyle.Render(text)
		case debug:
			text = debugStyle.Render(text)
		}
		rows = append(rows, text)
	}
	for len(rows) < m.height-1 {
		rows = append(rows, "")
	}
	footer := "e errors only  x/w/i/d/n toggle  a all  / search  r raw/safe  arrows scroll  q quit"
	if m.searching {
		footer = searchStyle.Render("SEARCH /" + m.query + "_")
	} else {
		footer = dimStyle.Render(crop(footer, 0, m.width))
	}
	rows = append(rows, footer)
	return strings.Join(rows, "\n")
}

func (m model) visible() []int {
	return m.rows
}

func (m *model) rebuildRows() {
	lines := m.safe
	if !m.sanitized {
		lines = m.raw
	}
	query := strings.ToLower(m.query)
	m.rows = m.rows[:0]
	for i, line := range lines {
		if m.enabled[m.levels[i]] && (query == "" || strings.Contains(strings.ToLower(line), query)) {
			m.rows = append(m.rows, i)
		}
	}
}

func (m *model) clamp() {
	visible := len(m.visible())
	maxTop := max(0, visible-m.pageHeight())
	m.top = min(max(0, m.top), maxTop)
	m.xoff = max(0, m.xoff)
}

func (m model) pageHeight() int { return max(1, m.height-3) }

func classify(lines []string) []level {
	levels := make([]level, len(lines))
	previous := neutral
	for i, line := range lines {
		upper := strings.ToUpper(line)
		switch {
		case containsAny(upper, " ERROR ", " FATAL ", "PANIC", "EXCEPTION", "FAILED", "FAILURE"):
			previous = errorLevel
		case containsAny(upper, " WARN ", "WARNING"):
			previous = warn
		case strings.Contains(upper, " INFO "):
			previous = info
		case containsAny(upper, " DEBUG ", " TRACE "):
			previous = debug
		case strings.HasPrefix(strings.TrimLeft(line, " \t"), "at ") || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "Caused by:"):
			// Stack trace continuations keep the initiating severity.
		default:
			previous = neutral
		}
		levels[i] = previous
	}
	return levels
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(s, value) {
			return true
		}
	}
	return false
}

func statusFlag(label string, on bool) string {
	if on {
		return "[" + label + "]"
	}
	return " " + label + " "
}

func crop(s string, offset, width int) string {
	runes := []rune(s)
	if offset >= len(runes) || width <= 0 {
		return ""
	}
	return string(runes[offset:min(len(runes), offset+width)])
}
