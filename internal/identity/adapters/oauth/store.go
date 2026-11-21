package oauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// PostgresOAuthStore implements fosite storage backed by PostgreSQL and an in-memory cache.
type PostgresOAuthStore struct {
	*storage.MemoryStore
	db *sql.DB
}

// NewPostgresOAuthStore initializes a new PostgresOAuthStore.
func NewPostgresOAuthStore(db *sql.DB) *PostgresOAuthStore {
	return &PostgresOAuthStore{
		MemoryStore: storage.NewMemoryStore(),
		db:          db,
	}
}

// RegisterClient registers an OAuth client in both PostgreSQL and the in-memory cache.
func (s *PostgresOAuthStore) RegisterClient(ctx context.Context, client *fosite.DefaultClient, clientName string) error {
	clientType := "PUBLIC"
	if len(client.Secret) > 0 {
		clientType = "CONFIDENTIAL"
	}

	if s.db != nil {
		query := `
			INSERT INTO identity.oauth_clients (
				client_id, client_name, client_type, secret_hash, redirect_uris, allowed_scopes, status, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', clock_timestamp())
			ON CONFLICT (client_id) DO UPDATE SET
				client_name = EXCLUDED.client_name,
				redirect_uris = EXCLUDED.redirect_uris,
				allowed_scopes = EXCLUDED.allowed_scopes,
				status = 'ACTIVE'
		`
		var secretParam any = nil
		if clientType == "CONFIDENTIAL" && len(client.Secret) > 0 {
			secretParam = client.Secret
		}

		_, err := s.db.ExecContext(ctx, query,
			client.ID,
			clientName,
			clientType,
			secretParam,
			pq.Array(client.RedirectURIs),
			pq.Array(client.Scopes),
		)
		if err != nil {
			return fmt.Errorf("failed to register oauth client in postgres: %w", err)
		}
	}

	s.MemoryStore.Clients[client.ID] = client
	return nil
}

// GetClient retrieves an active OAuth client by client ID from PostgreSQL or memory.
func (s *PostgresOAuthStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if s.db != nil {
		query := `
			SELECT client_id, client_type, secret_hash, redirect_uris, allowed_scopes, status
			FROM identity.oauth_clients
			WHERE client_id = $1 AND status = 'ACTIVE'
		`
		var (
			clientID      string
			clientType    string
			secretHash    []byte
			redirectURIs  []string
			allowedScopes []string
			status        string
		)
		err := s.db.QueryRowContext(ctx, query, id).Scan(
			&clientID, &clientType, &secretHash, pq.Array(&redirectURIs), pq.Array(&allowedScopes), &status,
		)
		if err == nil {
			c := &fosite.DefaultClient{
				ID:            clientID,
				Secret:        secretHash,
				RedirectURIs:  redirectURIs,
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
				Scopes:        allowedScopes,
				Public:        clientType == "PUBLIC",
			}
			s.MemoryStore.Clients[clientID] = c
			return c, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("failed to query oauth client: %w", err)
		}
	}

	return s.MemoryStore.GetClient(ctx, id)
}

// CreateAuthorizeCodeSession stores the authorization code session in memory and PostgreSQL.
func (s *PostgresOAuthStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	if err := s.MemoryStore.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		return err
	}

	if s.db == nil {
		return nil
	}

	codeHash := sha256.Sum256([]byte(code))
	clientID := req.GetClient().GetID()

	var clientUUID string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM identity.oauth_clients WHERE client_id = $1", clientID).Scan(&clientUUID)
	if err != nil {
		return fmt.Errorf("failed to find oauth client uuid: %w", err)
	}

	userID := req.GetSession().GetSubject()
	if strings.TrimSpace(userID) == "" {
		return errors.New("missing user id in session")
	}

	redirectURI := req.GetRequestForm().Get("redirect_uri")

	pkceChallenge := req.GetRequestForm().Get("code_challenge")
	pkceMethod := req.GetRequestForm().Get("code_challenge_method")
	if pkceMethod == "" {
		pkceMethod = "S256"
	}

	scopes := make([]string, 0)
	for _, sc := range req.GetGrantedScopes() {
		scopes = append(scopes, sc)
	}

	expiresAt := time.Now().UTC().Add(10 * time.Minute)

	insertQuery := `
		INSERT INTO identity.oauth_authorization_codes (
			code_hash, client_id, user_id, redirect_uri, scopes,
			pkce_challenge, pkce_method, expires_at, issued_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, clock_timestamp())
	`
	_, err = s.db.ExecContext(ctx, insertQuery,
		codeHash[:],
		clientUUID,
		userID,
		redirectURI,
		pq.Array(scopes),
		pkceChallenge,
		pkceMethod,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to persist authorization code: %w", err)
	}

	return nil
}

// GetAuthorizeCodeSession hydrates and returns the session, verifying single-use consumption in PostgreSQL.
func (s *PostgresOAuthStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	if s.db != nil {
		codeHash := sha256.Sum256([]byte(code))
		var usedAt sql.NullTime
		var expiresAt time.Time

		err := s.db.QueryRowContext(ctx, `
			SELECT used_at, expires_at
			FROM identity.oauth_authorization_codes
			WHERE code_hash = $1
		`, codeHash[:]).Scan(&usedAt, &expiresAt)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fosite.ErrNotFound
			}
			return nil, fmt.Errorf("failed to query authorization code: %w", err)
		}

		if usedAt.Valid {
			// Code reuse detected!
			req, memErr := s.MemoryStore.GetAuthorizeCodeSession(ctx, code, session)
			if memErr == nil && req != nil {
				return req, fosite.ErrInvalidatedAuthorizeCode
			}
			return nil, fosite.ErrInvalidatedAuthorizeCode
		}

		if expiresAt.Before(time.Now().UTC()) {
			return nil, fosite.ErrTokenExpired
		}
	}

	return s.MemoryStore.GetAuthorizeCodeSession(ctx, code, session)
}

// InvalidateAuthorizeCodeSession marks an authorization code as consumed, preventing replay attacks.
func (s *PostgresOAuthStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	if s.db != nil {
		codeHash := sha256.Sum256([]byte(code))
		res, err := s.db.ExecContext(ctx, `
			UPDATE identity.oauth_authorization_codes
			SET used_at = clock_timestamp()
			WHERE code_hash = $1 AND used_at IS NULL
		`, codeHash[:])
		if err != nil {
			return fmt.Errorf("failed to invalidate authorization code in postgres: %w", err)
		}

		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return fosite.ErrInvalidatedAuthorizeCode
		}
	}

	return s.MemoryStore.InvalidateAuthorizeCodeSession(ctx, code)
}
