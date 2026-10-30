package auth

import "testing"

func TestStrictJSONNeverSubstitutesAnInvalidIdentityString(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("{\"sub\":\"\xff\"}"),
		[]byte(`{"sub":"\ud800"}`), []byte(`{"sub":"\udc00"}`), []byte(`{"sub":"\ud800x"}`),
		[]byte(`{"sub":"\ud800\ud800"}`), []byte(`{"\ud800":"value"}`),
	} {
		if ValidateJSONObject(raw) == nil {
			t.Fatal("invalid Unicode was silently replaced")
		}
	}
	for _, raw := range []string{`{"sub":"\ud83d\ude42"}`, `{"sub":"\\ud800"}`, `{"sub":"学校用户"}`, `{"sub":"\ufffd"}`} {
		if err := ValidateJSONObject([]byte(raw)); err != nil {
			t.Fatal("valid identity string was rejected", err)
		}
	}
}
