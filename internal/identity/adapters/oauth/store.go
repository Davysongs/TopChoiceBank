package oauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
)

func setSessionSubject(session fosite.Session, userID string) fosite.Session {
	if session == nil {
		return &openid.DefaultSession{Subject: userID}
	}
	if s, ok := session.(*openid.DefaultSession); ok {
		s.Subject = userID
		return s
	}
	if s, ok := session.(*fosite.DefaultSession); ok {
		s.Subject = userID
		return s
	}
	return session
}

// PostgresOAuthStore implements fosite storage backed by PostgreSQL and an in-memory cache.
type PostgresOAuthStore struct {
	*storage.MemoryStore
	db               *sql.DB
	consumedConsents map[string]time.Time
	consumedMu       sync.RWMutex
}

// NewPostgresOAuthStore initializes a new PostgresOAuthStore.
func NewPostgresOAuthStore(db *sql.DB) *PostgresOAuthStore {
	return &PostgresOAuthStore{
		MemoryStore:      storage.NewMemoryStore(),
		db:               db,
		consumedConsents: make(map[string]time.Time),
	}
}

// ConsumeConsentID atomically marks a consent token identifier as consumed in PostgreSQL or memory.
func (s *PostgresOAuthStore) ConsumeConsentID(ctx context.Context, consentID string) error {
	if s.db != nil {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO identity.oauth_consumed_consents (consent_id, consumed_at)
			VALUES ($1, clock_timestamp())
		`, consentID)
		if err != nil {
			var pqErr *pq.Error
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				return errors.New("consent token has already been consumed")
			}
			return fmt.Errorf("failed to record consumed consent token: %w", err)
		}
		return nil
	}

	s.consumedMu.Lock()
	defer s.consumedMu.Unlock()
	if _, exists := s.consumedConsents[consentID]; exists {
		return errors.New("consent token has already been consumed")
	}
	s.consumedConsents[consentID] = time.Now().UTC()
	return nil
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
				client_type = EXCLUDED.client_type,
				secret_hash = EXCLUDED.secret_hash,
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
			return c, nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to query oauth client: %w", err)
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
		var (
			usedAt        sql.NullTime
			expiresAt     time.Time
			clientID      string
			userID        string
			redirectURI   string
			scopes        []string
			pkceChallenge string
			pkceMethod    string
		)

		err := s.db.QueryRowContext(ctx, `
			SELECT c.client_id, a.user_id, a.redirect_uri, a.scopes,
			       a.pkce_challenge, a.pkce_method, a.expires_at, a.used_at
			FROM identity.oauth_authorization_codes a
			JOIN identity.oauth_clients c ON a.client_id = c.id
			WHERE a.code_hash = $1
		`, codeHash[:]).Scan(
			&clientID, &userID, &redirectURI, pq.Array(&scopes),
			&pkceChallenge, &pkceMethod, &expiresAt, &usedAt,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fosite.ErrNotFound
			}
			return nil, fmt.Errorf("failed to query authorization code: %w", err)
		}

		if usedAt.Valid {
			// Code reuse detected!
			req, memErr := s.MemoryStore.GetAuthorizeCodeSession(ctx, code, session)
			if req != nil && (memErr == nil || errors.Is(memErr, fosite.ErrInvalidatedAuthorizeCode)) {
				return req, fosite.ErrInvalidatedAuthorizeCode
			}
			// Reconstruct req from DB so Fosite can revoke tokens on code reuse
			client, _ := s.GetClient(ctx, clientID)
			sess := setSessionSubject(session, userID)
			reconstructed := &fosite.Request{
				Client:         client,
				RequestedScope: fosite.Arguments(scopes),
				GrantedScope:   fosite.Arguments(scopes),
				Form: url.Values{
					"redirect_uri":          {redirectURI},
					"code_challenge":        {pkceChallenge},
					"code_challenge_method": {pkceMethod},
				},
				Session:     sess,
				RequestedAt: expiresAt.Add(-10 * time.Minute),
			}
			return reconstructed, fosite.ErrInvalidatedAuthorizeCode
		}

		if expiresAt.Before(time.Now().UTC()) {
			return nil, fosite.ErrTokenExpired
		}

		req, err := s.MemoryStore.GetAuthorizeCodeSession(ctx, code, session)
		if err == nil && req != nil {
			return req, nil
		}

		// Reconstruct from DB when MemoryStore does not contain it
		client, clientErr := s.GetClient(ctx, clientID)
		if clientErr != nil {
			return nil, clientErr
		}
		sess := setSessionSubject(session, userID)
		reconstructed := &fosite.Request{
			Client:         client,
			RequestedScope: fosite.Arguments(scopes),
			GrantedScope:   fosite.Arguments(scopes),
			Form: url.Values{
				"redirect_uri":          {redirectURI},
				"code_challenge":        {pkceChallenge},
				"code_challenge_method": {pkceMethod},
			},
			Session:     sess,
			RequestedAt: expiresAt.Add(-10 * time.Minute),
		}
		return reconstructed, nil
	}

	return s.MemoryStore.GetAuthorizeCodeSession(ctx, code, session)
}

// GetPKCERequestSession retrieves the PKCE requester session from memory or PostgreSQL.
func (s *PostgresOAuthStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, err := s.MemoryStore.GetPKCERequestSession(ctx, signature, session)
	if err == nil && req != nil {
		return req, nil
	}

	if s.db != nil {
		codeHash := sha256.Sum256([]byte(signature))
		var (
			clientID      string
			userID        string
			redirectURI   string
			scopes        []string
			pkceChallenge string
			pkceMethod    string
			expiresAt     time.Time
			usedAt        sql.NullTime
		)

		err := s.db.QueryRowContext(ctx, `
			SELECT c.client_id, a.user_id, a.redirect_uri, a.scopes,
			       a.pkce_challenge, a.pkce_method, a.expires_at, a.used_at
			FROM identity.oauth_authorization_codes a
			JOIN identity.oauth_clients c ON a.client_id = c.id
			WHERE a.code_hash = $1
		`, codeHash[:]).Scan(
			&clientID, &userID, &redirectURI, pq.Array(&scopes),
			&pkceChallenge, &pkceMethod, &expiresAt, &usedAt,
		)
		if err == nil {
			client, clientErr := s.GetClient(ctx, clientID)
			if clientErr != nil {
				return nil, clientErr
			}
			sess := setSessionSubject(session, userID)
			reconstructed := &fosite.Request{
				Client:         client,
				RequestedScope: fosite.Arguments(scopes),
				GrantedScope:   fosite.Arguments(scopes),
				Form: url.Values{
					"redirect_uri":          {redirectURI},
					"code_challenge":        {pkceChallenge},
					"code_challenge_method": {pkceMethod},
				},
				Session:     sess,
				RequestedAt: expiresAt.Add(-10 * time.Minute),
			}
			return reconstructed, nil
		}
	}

	return nil, fosite.ErrNotFound
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
