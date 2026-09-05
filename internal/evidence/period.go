package evidence

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Period is the window an evidence package covers, half-open: an entry at
// exactly To belongs to the next period.
//
// Half-open is the whole reason this type exists rather than two loose times.
// Quarters written as "July 1 to September 30" overlap at the boundary with
// whatever the next report calls its start, and one entry counted in two
// reports is a discrepancy an auditor will find and you will then have to
// explain. Closing the interval at one end removes the question.
type Period struct {
	Label string
	From  time.Time
	To    time.Time
}

// ParsePeriod reads the forms people actually write.
//
//	2026-Q3                    a calendar quarter
//	2026-09                    a calendar month
//	2026                       a calendar year
//	2026-07-01..2026-10-01     an explicit half-open range
//
// Everything is UTC, because the log is written in UTC and a report whose
// boundaries moved with the reader's timezone would not be evidence of the same
// thing twice.
func ParsePeriod(s string) (Period, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Period{}, fmt.Errorf("no period given")
	}

	if from, to, ok := strings.Cut(s, ".."); ok {
		f, err := parseDay(from)
		if err != nil {
			return Period{}, err
		}
		t, err := parseDay(to)
		if err != nil {
			return Period{}, err
		}
		if !f.Before(t) {
			return Period{}, fmt.Errorf("period %q ends before it starts", s)
		}
		return Period{Label: s, From: f, To: t}, nil
	}

	if year, q, ok := strings.Cut(strings.ToUpper(s), "-Q"); ok {
		y, err := strconv.Atoi(year)
		if err != nil {
			return Period{}, badPeriod(s)
		}
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 4 {
			return Period{}, fmt.Errorf("%q: a quarter is Q1 through Q4", s)
		}
		from := time.Date(y, time.Month(1+3*(n-1)), 1, 0, 0, 0, 0, time.UTC)
		return Period{Label: s, From: from, To: from.AddDate(0, 3, 0)}, nil
	}

	switch len(s) {
	case 4: // 2026
		y, err := strconv.Atoi(s)
		if err != nil {
			return Period{}, badPeriod(s)
		}
		from := time.Date(y, time.January, 1, 0, 0, 0, 0, time.UTC)
		return Period{Label: s, From: from, To: from.AddDate(1, 0, 0)}, nil
	case 7: // 2026-09
		from, err := time.Parse("2006-01", s)
		if err != nil {
			return Period{}, badPeriod(s)
		}
		from = from.UTC()
		return Period{Label: s, From: from, To: from.AddDate(0, 1, 0)}, nil
	case 10: // a single day
		from, err := parseDay(s)
		if err != nil {
			return Period{}, err
		}
		return Period{Label: s, From: from, To: from.AddDate(0, 0, 1)}, nil
	}
	return Period{}, badPeriod(s)
}

func parseDay(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, badPeriod(s)
	}
	return t.UTC(), nil
}

func badPeriod(s string) error {
	return fmt.Errorf("%q: want a quarter (2026-Q3), a month (2026-09), a year "+
		"(2026), a day (2026-09-04), or a range (2026-07-01..2026-10-01)", s)
}

// String renders the window the way the package states it, including the fact
// that the end is exclusive.
func (p Period) String() string {
	return fmt.Sprintf("%s — %s up to but not including %s",
		p.Label, p.From.Format("2006-01-02"), p.To.Format("2006-01-02"))
}

// Contains reports whether a moment falls inside the window.
func (p Period) Contains(t time.Time) bool {
	return !t.Before(p.From) && t.Before(p.To)
}
