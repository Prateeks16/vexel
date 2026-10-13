package store

import (
	"context"
	"time"
)

// AccessEvent is one access decision or sign-in, as shown in the access log.
type AccessEvent struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"-"`
	At        time.Time `json:"at"`
	Type      string    `json:"type"`
	App       string    `json:"app,omitempty"`
	Connector string    `json:"connector,omitempty"`
	User      string    `json:"user,omitempty"`
	Device    string    `json:"device,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Method    string    `json:"method,omitempty"`
	Host      string    `json:"host,omitempty"`
	Path      string    `json:"path,omitempty"`
	Policy    string    `json:"policy,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Edge      string    `json:"edge,omitempty"`
}

// AccessQuery filters one tenant's access log. Zero fields don't filter.
type AccessQuery struct {
	TenantID     string
	User         string   // exact email
	App          string   // app ID
	Types        []string // any of
	PathContains string   // case-insensitive substring
	From, To     time.Time
	// Cursor: only events strictly older than (BeforeAt, BeforeID).
	BeforeAt time.Time
	BeforeID string
	Limit    int // default 100
}

// AccessLog stores access events. It is separate from Store so a
// column store such as ClickHouse can take over at higher volume.
type AccessLog interface {
	// InsertAccessEvents ignores events whose ID is already stored, so
	// emitters can retry batches safely.
	InsertAccessEvents(ctx context.Context, events []AccessEvent) error
	// QueryAccessEvents returns matching events newest first.
	QueryAccessEvents(ctx context.Context, q AccessQuery) ([]AccessEvent, error)
	// PurgeAccessEvents deletes events older than before (retention).
	PurgeAccessEvents(ctx context.Context, before time.Time) (int64, error)
}

// ConnectorSession is one live tunnel between a connector and an edge.
type ConnectorSession struct {
	ConnectorID string    `json:"-"`
	Edge        string    `json:"edge"`
	Remote      string    `json:"remote"`
	Hostname    string    `json:"hostname,omitempty"`
	Version     string    `json:"version,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
	ReportedAt  time.Time `json:"reported_at"`
}

// staleReport is how long rows from an edge that stopped reporting are kept.
const staleReport = time.Hour

func defaultLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return n
}
