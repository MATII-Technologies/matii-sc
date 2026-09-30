package matii

import (
	"encoding/json"
	"sort"
	"strings"
)

// Map returns key -> value, skipping redacted secrets. Later paths win on duplicates.
func Map(secrets []Secret) map[string]string {
	out := map[string]string{}
	for _, s := range secrets {
		if !s.Redacted {
			out[s.Key] = s.Value
		}
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

// Dotenv renders KEY="value" lines with \\, ", \n and \r escaped.
func Dotenv(secrets []Secret) string {
	m := Map(secrets)
	var b strings.Builder
	for _, k := range sortedKeys(m) {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(m[k])
		b.WriteString(k + `="` + v + "\"\n")
	}
	return b.String()
}

// ShellExports renders `export KEY='value'` lines safe for POSIX shells.
func ShellExports(secrets []Secret) string {
	m := Map(secrets)
	var b strings.Builder
	for _, k := range sortedKeys(m) {
		b.WriteString("export " + k + "='" + strings.ReplaceAll(m[k], "'", `'"'"'`) + "'\n")
	}
	return b.String()
}

// JSON renders {"KEY": "value"}.
func JSON(secrets []Secret) string {
	b, _ := json.MarshalIndent(Map(secrets), "", "  ")
	return string(b) + "\n"
}
