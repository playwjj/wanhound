package i18n

import (
	"encoding/json"
	"regexp"
	"testing"
)

var verb = regexp.MustCompile(`%(\[[0-9]+\])?[-+# 0]*[0-9]*[sdqv]`)

// Every key exists in both languages with the same placeholders, so a
// translation can never drop or reorder an argument.
func TestCatalogParity(t *testing.T) {
	for _, k := range Keys(EN) {
		zh, ok := catalog[ZH][k]
		if !ok {
			t.Errorf("zh missing %q", k)
			continue
		}
		if a, b := len(verb.FindAllString(catalog[EN][k], -1)), len(verb.FindAllString(zh, -1)); a != b {
			t.Errorf("%q: en has %d placeholders, zh has %d", k, a, b)
		}
	}
	for _, k := range Keys(ZH) {
		if _, ok := catalog[EN][k]; !ok {
			t.Errorf("en missing %q", k)
		}
	}
}

func TestMsgRenderAndJSON(t *testing.T) {
	m := M("diff.coverage", 3, "@portset.full", "@portset.quick")
	if got := m.Render(ZH); got != "有 3 个开放端口不在另一次扫描的端口范围内，未参与对比（全端口扫描 对比 快速扫描）" {
		t.Errorf("zh render = %q", got)
	}
	b, _ := json.Marshal(m)
	var back Msg
	if err := json.Unmarshal(b, &back); err != nil || back.Render(EN) != m.Render(EN) {
		t.Errorf("round trip: %s → %+v (%v)", b, back, err)
	}
	var old Msg
	json.Unmarshal([]byte(`"plain v0.2.0 note"`), &old)
	if old.Render(ZH) != "plain v0.2.0 note" {
		t.Errorf("legacy string = %+v", old)
	}
	if Normalize("zh_CN.UTF-8") != ZH || Normalize("en_US") != EN || Normalize("") != EN {
		t.Error("Normalize")
	}
}
