package store

import (
	"context"
	"time"
)

// Device is an enrolled trusted device: a hardware-bound WebAuthn credential
// belonging to one user.
type Device struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"-"`
	UserEmail    string     `json:"user"`
	Name         string     `json:"name"`
	CredentialID string     `json:"-"` // base64url WebAuthn credential ID
	Credential   []byte     `json:"-"` // serialized webauthn.Credential
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// DeviceEnrollment is a one-time link an admin issues to enroll a device for
// a user.
type DeviceEnrollment struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"-"`
	UserEmail  string     `json:"user"`
	Name       string     `json:"name"`
	CodeSHA256 string     `json:"-"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
}

// TrustedDevice is the slice of a device edges need to enforce policy.
type TrustedDevice struct {
	TenantID  string
	DeviceID  string
	UserEmail string
}

// DeviceStore is implemented by both stores; it is part of Store.
type DeviceStore interface {
	CreateDeviceEnrollment(ctx context.Context, e DeviceEnrollment) (DeviceEnrollment, error)
	// ListDeviceEnrollments returns unused, unexpired enrollments.
	ListDeviceEnrollments(ctx context.Context, tenantID string, now time.Time) ([]DeviceEnrollment, error)
	DeleteDeviceEnrollment(ctx context.Context, tenantID, id string) error
	// GetDeviceEnrollmentByCode returns a usable (unused, unexpired) enrollment.
	GetDeviceEnrollmentByCode(ctx context.Context, codeSHA256 string, now time.Time) (DeviceEnrollment, error)
	// CompleteDeviceEnrollment consumes the enrollment and creates the device
	// atomically, so a code can enroll at most one device.
	CompleteDeviceEnrollment(ctx context.Context, codeSHA256 string, d Device, now time.Time) (Device, error)

	ListDevices(ctx context.Context, tenantID string) ([]Device, error)
	// ListUserDevices returns the user's active (unrevoked) devices.
	ListUserDevices(ctx context.Context, tenantID, email string) ([]Device, error)
	// RecordDeviceUse stores the updated credential (sign counter) and time.
	RecordDeviceUse(ctx context.Context, tenantID, id string, credential []byte, at time.Time) error
	RevokeDevice(ctx context.Context, tenantID, id string, at time.Time) (Device, error)
}
