package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const enrollmentCols = "id, tenant_id, user_email, name, code_sha256, created_by, created_at, expires_at, used_at"

func scanEnrollment(row pgx.Row) (DeviceEnrollment, error) {
	var e DeviceEnrollment
	err := row.Scan(&e.ID, &e.TenantID, &e.UserEmail, &e.Name, &e.CodeSHA256, &e.CreatedBy, &e.CreatedAt, &e.ExpiresAt, &e.UsedAt)
	return e, mapErr(err, "enrollment")
}

func (p *Postgres) CreateDeviceEnrollment(ctx context.Context, e DeviceEnrollment) (DeviceEnrollment, error) {
	if !isUUID(e.TenantID) {
		return DeviceEnrollment{}, notFound("tenant")
	}
	e.ID, e.CreatedAt, e.UsedAt = NewID(), now(), nil
	e.ExpiresAt = e.ExpiresAt.UTC().Truncate(time.Microsecond)
	_, err := p.pool.Exec(ctx, "INSERT INTO device_enrollments ("+enrollmentCols+") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)",
		e.ID, e.TenantID, e.UserEmail, e.Name, e.CodeSHA256, e.CreatedBy, e.CreatedAt, e.ExpiresAt)
	if err != nil {
		return DeviceEnrollment{}, mapErr(err, "tenant")
	}
	return e, nil
}

func (p *Postgres) ListDeviceEnrollments(ctx context.Context, tenantID string, now time.Time) ([]DeviceEnrollment, error) {
	if !isUUID(tenantID) {
		return []DeviceEnrollment{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+enrollmentCols+` FROM device_enrollments
		WHERE tenant_id = $1 AND used_at IS NULL AND expires_at > $2 ORDER BY created_at DESC`, tenantID, now)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanEnrollment)
}

func (p *Postgres) DeleteDeviceEnrollment(ctx context.Context, tenantID, id string) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return notFound("enrollment")
	}
	tag, err := p.pool.Exec(ctx, "DELETE FROM device_enrollments WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	return expectOne(tag, "enrollment")
}

func (p *Postgres) GetDeviceEnrollmentByCode(ctx context.Context, code string, now time.Time) (DeviceEnrollment, error) {
	return scanEnrollment(p.pool.QueryRow(ctx, "SELECT "+enrollmentCols+` FROM device_enrollments
		WHERE code_sha256 = $1 AND used_at IS NULL AND expires_at > $2`, code, now))
}

func (p *Postgres) CompleteDeviceEnrollment(ctx context.Context, code string, d Device, at time.Time) (Device, error) {
	at = at.UTC().Truncate(time.Microsecond)
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// The conditional UPDATE is the single-use guarantee: of two racing
		// completions, only one sees used_at IS NULL.
		var e DeviceEnrollment
		err := tx.QueryRow(ctx, `UPDATE device_enrollments SET used_at = $3
			WHERE code_sha256 = $1 AND used_at IS NULL AND expires_at > $2
			RETURNING tenant_id, user_email, name`, code, at, at).Scan(&e.TenantID, &e.UserEmail, &e.Name)
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound("enrollment")
		}
		if err != nil {
			return err
		}
		d.ID, d.TenantID, d.UserEmail, d.Name, d.CreatedAt, d.LastUsedAt, d.RevokedAt = NewID(), e.TenantID, e.UserEmail, e.Name, at, nil, nil
		if _, err := tx.Exec(ctx, `INSERT INTO devices (id, tenant_id, user_email, name, credential_id, credential, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, d.ID, d.TenantID, d.UserEmail, d.Name, d.CredentialID, d.Credential, d.CreatedAt); err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	if errors.Is(err, ErrNotFound) {
		return Device{}, err
	}
	if err != nil {
		return Device{}, mapErr(err, "tenant")
	}
	return d, nil
}

const deviceCols = "id, tenant_id, user_email, name, credential_id, credential, created_at, last_used_at, revoked_at"

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.TenantID, &d.UserEmail, &d.Name, &d.CredentialID, &d.Credential, &d.CreatedAt, &d.LastUsedAt, &d.RevokedAt)
	return d, mapErr(err, "device")
}

func (p *Postgres) ListDevices(ctx context.Context, tenantID string) ([]Device, error) {
	if !isUUID(tenantID) {
		return []Device{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+deviceCols+` FROM devices WHERE tenant_id = $1
		ORDER BY user_email COLLATE "C", name COLLATE "C", id`, tenantID)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanDevice)
}

func (p *Postgres) ListUserDevices(ctx context.Context, tenantID, email string) ([]Device, error) {
	if !isUUID(tenantID) {
		return []Device{}, nil
	}
	rows, err := p.pool.Query(ctx, "SELECT "+deviceCols+` FROM devices
		WHERE tenant_id = $1 AND lower(user_email) = lower($2) AND revoked_at IS NULL
		ORDER BY name COLLATE "C", id`, tenantID, email)
	if err != nil {
		return nil, err
	}
	return collect(rows, scanDevice)
}

func (p *Postgres) RecordDeviceUse(ctx context.Context, tenantID, id string, credential []byte, at time.Time) error {
	if !isUUID(tenantID) || !isUUID(id) {
		return notFound("device")
	}
	tag, err := p.pool.Exec(ctx, "UPDATE devices SET credential = $3, last_used_at = $4 WHERE tenant_id = $1 AND id = $2",
		tenantID, id, credential, at.UTC())
	if err != nil {
		return err
	}
	return expectOne(tag, "device")
}

func (p *Postgres) RevokeDevice(ctx context.Context, tenantID, id string, at time.Time) (Device, error) {
	if !isUUID(tenantID) || !isUUID(id) {
		return Device{}, notFound("device")
	}
	var d Device
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var err error
		d, err = scanDevice(tx.QueryRow(ctx, `UPDATE devices SET revoked_at = COALESCE(revoked_at, $3)
			WHERE tenant_id = $1 AND id = $2 RETURNING `+deviceCols, tenantID, id, at.UTC()))
		if err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	return d, err
}
