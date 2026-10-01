package analysis

import (
	"testing"
	"time"

	"basb/internal/event"
)

func TestIsSensitiveAndCounts(t *testing.T) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	events := []event.Event{
		{
			Timestamp: base,
			Action:    event.ActionSpec{Category: event.CatFile, Type: event.TypeWrite},
			RiskLevel: event.RiskInfo,
		},
		{
			Timestamp: base.Add(time.Second),
			Action:    event.ActionSpec{Category: event.CatCredential, Type: event.TypeHit},
			RiskLevel: event.RiskHigh,
		},
		{
			Timestamp: base.Add(2 * time.Second),
			Action:    event.ActionSpec{Category: event.CatSensitive, Type: event.TypeHit},
			RiskLevel: event.RiskMedium,
		},
		{
			Timestamp: base.Add(3 * time.Second),
			Action:    event.ActionSpec{Category: event.CatPrivilege, Type: "elevate"},
			RiskLevel: event.RiskHigh,
		},
		{
			Timestamp: base.Add(4 * time.Second),
			Action:    event.ActionSpec{Category: event.CatSSH, Type: event.TypeHit},
			RiskLevel: event.RiskHigh,
		},
	}

	c := countEvents(events)
	if c.Credential != 1 {
		t.Fatalf("credential=%d want 1", c.Credential)
	}
	// credential + sensitive + privilege HIGH + ssh HIGH = 4 (no double-count)
	if c.Sensitive != 4 {
		t.Fatalf("sensitive=%d want 4", c.Sensitive)
	}

	sens := filterSensitive(events)
	if len(sens) != 4 {
		t.Fatalf("filterSensitive len=%d want 4", len(sens))
	}
	for _, item := range sens {
		if item.Timestamp == "" || item.Timestamp[len(item.Timestamp)-1] != 'Z' && item.Timestamp[len(item.Timestamp)-6] != '+' {
			// RFC3339Nano from UTC should end with Z
			if len(item.Timestamp) < 20 {
				t.Fatalf("timestamp not RFC3339: %q", item.Timestamp)
			}
		}
	}

	tl := makeTimeline(events, 0)
	if len(tl) != 5 {
		t.Fatalf("timeline len=%d want 5", len(tl))
	}
	for i := 1; i < len(tl); i++ {
		if tl[i].Timestamp < tl[i-1].Timestamp {
			t.Fatalf("timeline not sorted: %s before %s", tl[i-1].Timestamp, tl[i].Timestamp)
		}
	}
}

func TestIsSensitive(t *testing.T) {
	cases := []struct {
		cat  event.Category
		risk event.RiskLevel
		want bool
	}{
		{event.CatFile, event.RiskInfo, false},
		{event.CatCredential, event.RiskLow, true},
		{event.CatSensitive, event.RiskInfo, true},
		{event.CatPrivilege, event.RiskHigh, true},
		{event.CatPrivilege, event.RiskMedium, false},
		{event.CatSSH, event.RiskCritical, true},
	}
	for _, tc := range cases {
		ev := event.Event{
			Action:    event.ActionSpec{Category: tc.cat},
			RiskLevel: tc.risk,
		}
		if got := IsSensitive(ev); got != tc.want {
			t.Fatalf("%s/%s: got %v want %v", tc.cat, tc.risk, got, tc.want)
		}
	}
}
