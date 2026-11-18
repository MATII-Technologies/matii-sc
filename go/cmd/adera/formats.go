package main

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/MATII-Technologies/matii-sc/go/matii"
)

// exporters render key → value maps (sorted by key) in each export format.
var exporters = map[string]func(map[string]string) string{
	"dotenv": func(m map[string]string) string { return matii.Dotenv(toSecrets(m)) },
	"json":   func(m map[string]string) string { return matii.JSON(toSecrets(m)) },
	"shell":  func(m map[string]string) string { return matii.ShellExports(toSecrets(m)) },
	"csv": func(m map[string]string) string {
		var b bytes.Buffer
		w := csv.NewWriter(&b)
		_ = w.Write([]string{"Key", "Value"})
		for _, k := range sortedKeys(m) {
			_ = w.Write([]string{k, m[k]})
		}
		w.Flush()
		return b.String()
	},
	"yaml": func(m map[string]string) string {
		return lines(m, func(k, v string) string { return quoteKey(k) + ": " + jsonString(v) })
	},
	"toml": func(m map[string]string) string {
		return lines(m, func(k, v string) string { return quoteKey(k) + " = " + jsonString(v) })
	},
	"hcl": func(m map[string]string) string {
		// ${ and %{ start template sequences in HCL strings.
		escape := strings.NewReplacer("${", "$${", "%{", "%%{")
		return lines(m, func(k, v string) string { return quoteKey(k) + " = " + escape.Replace(jsonString(v)) })
	},
	"ini": func(m map[string]string) string {
		return "[DEFAULT]\n" + lines(m, func(k, v string) string { return k + " = " + escapeControl(v) })
	},
	"java_properties": func(m map[string]string) string {
		return lines(m, func(k, v string) string { return propertiesEscape(k, true) + "=" + propertiesEscape(v, false) })
	},
	"kv": func(m map[string]string) string {
		return lines(m, func(k, v string) string { return k + "=" + v })
	},
	"xml": func(m map[string]string) string {
		var b strings.Builder
		b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Secrets>\n")
		for _, k := range sortedKeys(m) {
			b.WriteString(`  <secret name="`)
			_ = xml.EscapeText(&b, []byte(k))
			b.WriteString(`">`)
			_ = xml.EscapeText(&b, []byte(m[k]))
			b.WriteString("</secret>\n")
		}
		b.WriteString("</Secrets>\n")
		return b.String()
	},
}

func exportFormats() []string {
	out := make([]string, 0, len(exporters))
	for f := range exporters {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func toSecrets(m map[string]string) []matii.Secret {
	out := make([]matii.Secret, 0, len(m))
	for k, v := range m {
		out = append(out, matii.Secret{Key: k, Value: v})
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func lines(m map[string]string, line func(k, v string) string) string {
	var b strings.Builder
	for _, k := range sortedKeys(m) {
		b.WriteString(line(k, m[k]) + "\n")
	}
	return b.String()
}

func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func quoteKey(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	return jsonString(k)
}

func escapeControl(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
}

// propertiesEscape follows java.util.Properties: backslash escapes, and
// \uXXXX for anything outside printable ASCII.
func propertiesEscape(s string, key bool) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '=' || r == ':' || r == '#' || r == '!':
			b.WriteString(`\` + string(r))
		case r == ' ' && (key || i == 0):
			b.WriteString(`\ `)
		case r < 0x20 || r > 0x7e:
			if r > 0xffff {
				for _, u := range utf16Pair(r) {
					fmt.Fprintf(&b, `\u%04x`, u)
				}
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// utf16Pair returns the surrogate pair of r as two runes.
func utf16Pair(r rune) []rune {
	r -= 0x10000
	return []rune{0xd800 + (r>>10)&0x3ff, 0xdc00 + r&0x3ff}
}

// --- .env parsing (secrets import) ---------------------------------------------------------

type dotenvEntry struct{ key, value string }

var dotenvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// parseDotenv reads KEY=VALUE lines: optional `export`, # comments, unquoted
// values (a " #" starts a comment), 'single-quoted' literal values and
// "double-quoted" values with \n \r \t \" \\ escapes; quoted values may span lines.
func parseDotenv(src string) ([]dotenvEntry, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	var out []dotenvEntry
	lineNo := 0
	rest := src
	for rest != "" {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		lineNo++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		key, value, ok := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if !ok || !dotenvKey.MatchString(key) {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNo)
		}
		value = strings.TrimLeft(value, " \t")
		if value != "" && (value[0] == '"' || value[0] == '\'') {
			quote := value[0]
			body := value[1:]
			for {
				if end := closingQuote(body, quote); end >= 0 {
					tail := strings.TrimSpace(body[end+1:])
					if tail != "" && !strings.HasPrefix(tail, "#") {
						return nil, fmt.Errorf("line %d: text after the closing quote", lineNo)
					}
					body = body[:end]
					break
				}
				if rest == "" {
					return nil, fmt.Errorf("line %d: unterminated quoted value", lineNo)
				}
				var next string
				next, rest, _ = strings.Cut(rest, "\n")
				lineNo++
				body += "\n" + next
			}
			if quote == '"' {
				body = strings.NewReplacer(`\\`, `\`, `\n`, "\n", `\r`, "\r", `\t`, "\t", `\"`, `"`).Replace(body)
			}
			out = append(out, dotenvEntry{key, body})
			continue
		}
		if i := strings.Index(value, " #"); i >= 0 {
			value = value[:i]
		}
		out = append(out, dotenvEntry{key, strings.TrimSpace(value)})
	}
	return out, nil
}

// closingQuote finds the unescaped closing quote (backslash escapes only in "...").
func closingQuote(s string, quote byte) int {
	for i := 0; i < len(s); i++ {
		if quote == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == quote {
			return i
		}
	}
	return -1
}

// --- GitHub Actions ------------------------------------------------------------------------------

// githubEnv masks every value line in the job log (workflow commands on
// stdout) and appends the variables to $GITHUB_ENV with random delimiters.
func githubEnv(secrets []matii.Secret, stdout io.Writer) error {
	envFile := os.Getenv("GITHUB_ENV")
	if envFile == "" {
		return errors.New("--format github only works inside GitHub Actions (GITHUB_ENV is not set)")
	}
	values := matii.Map(secrets)
	for _, value := range values {
		for _, line := range strings.Split(value, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Fprintf(stdout, "::add-mask::%s\n", line)
			}
		}
	}
	f, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	for key, value := range values {
		delimiter, err := randomDelimiter()
		if err != nil {
			return err
		}
		if strings.Contains(value, delimiter) {
			return errors.New("value contains the heredoc delimiter")
		}
		if _, err := fmt.Fprintf(f, "%s<<%s\n%s\n%s\n", key, delimiter, value, delimiter); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "Exported %d secret(s) to the job environment.\n", len(values))
	return nil
}

func randomDelimiter() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ADERA_EOF_" + hex.EncodeToString(b), nil
}
