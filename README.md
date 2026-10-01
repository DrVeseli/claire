# Claire

Claire sanitizes logs with reversible aliases and provides a terminal viewer for searching and filtering them.

## Install

Download the archive for your system from [Releases](../../releases), extract it, rename the binary to `claire` (`claire.exe` on Windows), and put it on your `PATH`.

Or build from source with Go 1.24 or newer:

```sh
go install github.com/DrVeseli/claire@v0.3
```

## Usage

```sh
./claire sanitize cloudbeaver.log
./claire restore -k key.txt sanitized_log.log
./claire cloudbeaver.log
./claire tui -k key.txt sanitized_log.log
```

`sanitize` writes `sanitized_log.log` and a private `key.txt`. Keep the key secret; it contains the original values.

## TUI keys

| Key | Action |
| --- | --- |
| `e` | Show errors only |
| `x` | Show/hide errors |
| `w`, `i`, `d`, `n` | Toggle warnings, info, debug, or unclassified lines |
| `a` | Show every severity |
| `/` | Search; `Enter` or `Esc` finishes editing |
| `c` | Clear search |
| `r` or `Tab` | Switch sanitized/raw preview |
| Arrows, `j`/`k`, PgUp/PgDn | Scroll |
| `q` | Quit |
