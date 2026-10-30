// Package i18n holds WanHound's user-facing message catalog (English
// and Simplified Chinese).
//
// Stored data stays language-neutral: snapshots keep a Msg (catalog key
// plus pre-formatted arguments) and every reader renders it in its own
// language. An argument starting with "@" is itself a catalog key, so
// messages can be composed ("override because @inside.egress").
package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Languages.
const (
	EN = "en"
	ZH = "zh"
)

// Normalize maps any language tag to EN or ZH.
func Normalize(lang string) string {
	l := strings.ToLower(strings.TrimSpace(lang))
	if strings.HasPrefix(l, "zh") {
		return ZH
	}
	return EN
}

// FromEnv picks the language from WANHOUND_LANG, then LC_ALL, LC_MESSAGES
// and LANG (so a zh_CN locale gets Chinese reports by default).
func FromEnv() string {
	for _, k := range []string{"WANHOUND_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			return Normalize(v)
		}
	}
	return EN
}

// T renders a catalog entry. Unknown keys render as the key itself, so a
// missing translation is visible rather than silent.
func T(lang, key string, args ...any) string {
	format, ok := catalog[Normalize(lang)][key]
	if !ok {
		if format, ok = catalog[EN][key]; !ok {
			return key
		}
	}
	if len(args) == 0 {
		return format
	}
	// Catalog formats use %s (and %q) only, so numbers and durations are
	// stringified first and translators never juggle verb types.
	for i, a := range args {
		if _, ok := a.(string); !ok {
			args[i] = fmt.Sprint(a)
		}
	}
	return fmt.Sprintf(format, args...)
}

// Msg is a renderable message: a catalog key with arguments. Text is a
// literal fallback (messages stored by older versions as plain strings).
type Msg struct {
	Key  string
	Args []string
	Text string
}

// M builds a Msg; arguments are formatted to strings immediately so the
// stored form is stable.
func M(key string, args ...any) Msg {
	m := Msg{Key: key}
	for _, a := range args {
		m.Args = append(m.Args, fmt.Sprint(a))
	}
	return m
}

// Render returns the message text in lang.
func (m Msg) Render(lang string) string {
	if m.Key == "" {
		return m.Text
	}
	args := make([]any, len(m.Args))
	for i, a := range m.Args {
		if strings.HasPrefix(a, "@") {
			args[i] = T(lang, a[1:])
		} else {
			args[i] = a
		}
	}
	return T(lang, m.Key, args...)
}

// String renders in English.
func (m Msg) String() string { return m.Render(EN) }

// Localized returns a copy whose JSON "text" is rendered in lang.
func (m Msg) Localized(lang string) Msg {
	m.Text = m.Render(lang)
	return m
}

type wire struct {
	Key  string   `json:"key,omitempty"`
	Args []string `json:"args,omitempty"`
	Text string   `json:"text"`
}

// MarshalJSON emits key, args and a rendered text (English unless the
// message was Localized), so JSON consumers always get readable text.
func (m Msg) MarshalJSON() ([]byte, error) {
	text := m.Text
	if text == "" {
		text = m.Render(EN)
	}
	return json.Marshal(wire{Key: m.Key, Args: m.Args, Text: text})
}

// UnmarshalJSON accepts the object form and, for snapshots written by
// v0.2.0, a plain string.
func (m *Msg) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*m = Msg{Text: s}
		return nil
	}
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*m = Msg{Key: w.Key, Args: w.Args}
	if w.Key == "" {
		m.Text = w.Text
	}
	return nil
}

// LocalizeAll localizes a slice in place-safe copy.
func LocalizeAll(ms []Msg, lang string) []Msg {
	out := make([]Msg, len(ms))
	for i, m := range ms {
		out[i] = m.Localized(lang)
	}
	return out
}

// Keys lists every catalog key of a language (for tests).
func Keys(lang string) []string {
	var ks []string
	for k := range catalog[lang] {
		ks = append(ks, k)
	}
	return ks
}
