package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type OutboxEventInput struct {
	AggregateType    string
	AggregateID      string
	AggregateVersion int64
	EventType        string
	SchemaVersion    int
	Payload          map[string]any
	Headers          map[string]any
	OccurredAt       time.Time
}

func AppendOutboxEvent(ctx context.Context, tx *sql.Tx, input OutboxEventInput) error {
	if tx == nil {
		return fmt.Errorf("transaction is required to append outbox event")
	}
	if input.OccurredAt.IsZero() {
		input.OccurredAt = time.Now().UTC()
	}
	if input.Headers == nil {
		input.Headers = make(map[string]any)
	}

	payloadBytes, err := json.Marshal(input.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal outbox event payload: %w", err)
	}

	headersBytes, err := json.Marshal(input.Headers)
	if err != nil {
		return fmt.Errorf("failed to marshal outbox event headers: %w", err)
	}

	query := `
		INSERT INTO events.outbox_events (
			aggregate_type, aggregate_id, aggregate_version,
			event_type, schema_version, payload, headers, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = tx.ExecContext(
		ctx,
		query,
		input.AggregateType,
		input.AggregateID,
		input.AggregateVersion,
		input.EventType,
		input.SchemaVersion,
		payloadBytes,
		headersBytes,
		input.OccurredAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert outbox event: %w", err)
	}

	return nil
}

