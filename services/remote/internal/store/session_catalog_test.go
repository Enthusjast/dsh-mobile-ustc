package store

import "testing"

func TestMobileSessionIDMatchesDSHUUIDv5Mapping(t *testing.T) {
	got, err := MobileSessionID("33333333-3333-4333-8333-333333333333", "native:中文/42")
	if err != nil {
		t.Fatal(err)
	}
	const want = "1c6bb930-979b-5043-8b44-71f62e126939"
	if got != want {
		t.Fatalf("mobile session ID=%s, want %s", got, want)
	}
}

func TestMobileSessionIDRejectsInvalidRuntimeAndNativeIDs(t *testing.T) {
	for _, test := range []struct {
		runtimeID string
		nativeID  string
	}{
		{runtimeID: "not-a-uuid", nativeID: "session"},
		{runtimeID: "33333333-3333-4333-8333-333333333333", nativeID: ""},
		{runtimeID: "33333333-3333-4333-8333-333333333333", nativeID: "bad\x00session"},
	} {
		if _, err := MobileSessionID(test.runtimeID, test.nativeID); err == nil {
			t.Fatalf("accepted runtime=%q native=%q", test.runtimeID, test.nativeID)
		}
	}
}
