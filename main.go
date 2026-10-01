package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "claire:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing command or log file")
	}
	if args[0] != "sanitize" && args[0] != "restore" && args[0] != "tui" && args[0] != "help" {
		return runTUI(args)
	}

	switch args[0] {
	case "sanitize":
		fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
		output := fs.String("o", "sanitized_log.log", "sanitized output")
		keyPath := fs.String("k", "key.txt", "reversal key")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: claire sanitize [-o sanitized_log.log] [-k key.txt] <log>")
		}
		input, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		safe, key := Sanitize(string(input))
		if sameFile(fs.Arg(0), *output) || sameFile(fs.Arg(0), *keyPath) || sameFile(*output, *keyPath) {
			return errors.New("input, output, and key paths must be different")
		}
		if err := writeAtomic(*output, []byte(safe), 0644); err != nil {
			return err
		}
		if err := WriteKey(*keyPath, key); err != nil {
			return err
		}
		fmt.Printf("sanitized %s -> %s (%d aliases)\nkey -> %s\n", fs.Arg(0), *output, len(key.Entries), *keyPath)
		return nil

	case "restore":
		fs := flag.NewFlagSet("restore", flag.ContinueOnError)
		output := fs.String("o", "restored_log.log", "restored output")
		keyPath := fs.String("k", "key.txt", "reversal key")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: claire restore [-k key.txt] [-o restored_log.log] <sanitized-log>")
		}
		safe, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		key, err := ReadKey(*keyPath)
		if err != nil {
			return err
		}
		raw, err := Restore(string(safe), key)
		if err != nil {
			return err
		}
		if sameFile(fs.Arg(0), *output) || sameFile(*keyPath, *output) {
			return errors.New("output must not overwrite the sanitized log or key")
		}
		return writeAtomic(*output, []byte(raw), 0600)

	case "tui":
		return runTUI(args[1:])
	default:
		usage()
		return nil
	}
}

func runTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	keyPath := fs.String("k", "", "key for an existing sanitized log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: claire tui [-k key.txt] <log>")
	}
	content, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	raw, safe := string(content), ""
	if *keyPath == "" {
		safe, _ = Sanitize(raw)
	} else {
		key, err := ReadKey(*keyPath)
		if err != nil {
			return err
		}
		safe = raw
		raw, err = Restore(safe, key)
		if err != nil {
			return err
		}
	}
	_, err = tea.NewProgram(newModel(filepath.Base(fs.Arg(0)), raw, safe), tea.WithAltScreen()).Run()
	return err
}

func usage() {
	fmt.Print(`claire - reversible log sanitization and inspection

Usage:
	claire sanitize [-o sanitized_log.log] [-k key.txt] <log>
	claire restore [-k key.txt] [-o restored_log.log] <sanitized-log>
	claire tui [-k key.txt] <log>
  claire <log>                         shorthand for tui
`)
}

func sameFile(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return aa == bb
}
