package store

import (
	"context"
	"slices"
	"strings"
	"time"
)

func (m *Memory) CreateDeviceEnrollment(_ context.Context, e DeviceEnrollment) (DeviceEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[e.TenantID]; !ok {
		return DeviceEnrollment{}, notFound("tenant")
	}
	e.ID, e.CreatedAt, e.UsedAt = NewID(), now(), nil
	e.ExpiresAt = e.ExpiresAt.UTC().Truncate(time.Microsecond)
	if m.enrollments == nil {
		m.enrollments = map[string]DeviceEnrollment{}
	}
	m.enrollments[e.ID] = e
	return e, nil
}

func usable(e DeviceEnrollment, now time.Time) bool {
	return e.UsedAt == nil && now.Before(e.ExpiresAt)
}

func (m *Memory) ListDeviceEnrollments(_ context.Context, tenantID string, now time.Time) ([]DeviceEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []DeviceEnrollment{}
	for _, e := range m.enrollments {
		if e.TenantID == tenantID && usable(e, now) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b DeviceEnrollment) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (m *Memory) DeleteDeviceEnrollment(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.enrollments[id]; !ok || e.TenantID != tenantID {
		return notFound("enrollment")
	}
	delete(m.enrollments, id)
	return nil
}

func (m *Memory) enrollmentByCode(code string, now time.Time) (DeviceEnrollment, bool) {
	for _, e := range m.enrollments {
		if e.CodeSHA256 == code && usable(e, now) {
			return e, true
		}
	}
	return DeviceEnrollment{}, false
}

func (m *Memory) GetDeviceEnrollmentByCode(_ context.Context, code string, now time.Time) (DeviceEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.enrollmentByCode(code, now); ok {
		return e, nil
	}
	return DeviceEnrollment{}, notFound("enrollment")
}

func (m *Memory) CompleteDeviceEnrollment(_ context.Context, code string, d Device, at time.Time) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrollmentByCode(code, at)
	if !ok {
		return Device{}, notFound("enrollment")
	}
	for _, x := range m.devices {
		if x.CredentialID == d.CredentialID {
			return Device{}, conflict("devices_credential_unique")
		}
	}
	at = at.UTC().Truncate(time.Microsecond)
	e.UsedAt = &at
	m.enrollments[e.ID] = e
	d.ID, d.TenantID, d.UserEmail, d.Name = NewID(), e.TenantID, e.UserEmail, e.Name
	d.CreatedAt, d.LastUsedAt, d.RevokedAt = at, nil, nil
	d.Credential = slices.Clone(d.Credential)
	if m.devices == nil {
		m.devices = map[string]Device{}
	}
	m.devices[d.ID] = d
	m.revision++
	return d, nil
}

func (m *Memory) ListDevices(_ context.Context, tenantID string) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Device{}
	for _, d := range sortedValues(m.devices, func(d Device) string { return d.UserEmail + "\x00" + d.Name + "\x00" + d.ID }) {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *Memory) ListUserDevices(_ context.Context, tenantID, email string) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Device{}
	for _, d := range sortedValues(m.devices, func(d Device) string { return d.Name + "\x00" + d.ID }) {
		if d.TenantID == tenantID && strings.EqualFold(d.UserEmail, email) && d.RevokedAt == nil {
			out = append(out, d)
		}
	}
	return out, nil
}

func (m *Memory) RecordDeviceUse(_ context.Context, tenantID, id string, credential []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.TenantID != tenantID {
		return notFound("device")
	}
	at = at.UTC().Truncate(time.Microsecond)
	d.Credential, d.LastUsedAt = slices.Clone(credential), &at
	m.devices[id] = d
	return nil
}

func (m *Memory) RevokeDevice(_ context.Context, tenantID, id string, at time.Time) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.TenantID != tenantID {
		return Device{}, notFound("device")
	}
	if d.RevokedAt == nil {
		at = at.UTC().Truncate(time.Microsecond)
		d.RevokedAt = &at
		m.devices[id] = d
		m.revision++
	}
	return d, nil
}
