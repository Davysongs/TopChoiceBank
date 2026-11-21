package platformhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"

	"github.com/Davysongs/TopChoiceBank/internal/identity/adapters/oauth"
	"github.com/Davysongs/TopChoiceBank/internal/platform/security"
)

// RegisterOAuthRoutes registers the OAuth 2.0 authorization and token endpoints on the router.
func RegisterOAuthRoutes(router *Router, adapter *oauth.OAuthAdapter, jwtSecret string) {
	RegisterOAuthTokenVerifier(func(ctx context.Context, tokenStr string) (*security.JWTClaims, error) {
		session := &fosite.DefaultSession{}
		_, ar, err := adapter.Provider().IntrospectToken(ctx, tokenStr, fosite.AccessToken, session)
		if err != nil {
			return nil, err
		}
		return &security.JWTClaims{
			Subject: ar.GetSession().GetSubject(),
			Scopes:  ar.GetGrantedScopes(),
			Issuer:  "topchoicebank",
		}, nil
	})

	router.HandleFunc("/v1/oauth/authorize", handleOAuthAuthorize(adapter, jwtSecret))
	router.HandleFunc("/v1/oauth/token", handleOAuthToken(adapter))
}

// handleOAuthAuthorize routes GET authorization requests and POST consent confirmations.
func handleOAuthAuthorize(adapter *oauth.OAuthAdapter, jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleOAuthAuthorizeGet(w, r, adapter, jwtSecret)
		case http.MethodPost:
			handleOAuthAuthorizePost(w, r, adapter)
		default:
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "GET or POST is required", r.URL.Path)
		}
	}
}

// handleOAuthAuthorizeGet validates the partner authorization request and returns consent metadata.
func handleOAuthAuthorizeGet(w http.ResponseWriter, r *http.Request, adapter *oauth.OAuthAdapter, jwtSecret string) {
	claims, ok := authenticateBearer(w, r, jwtSecret)
	if !ok {
		return
	}

	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if codeChallengeMethod != "S256" {
		writeProblem(w, http.StatusBadRequest, "Invalid PKCE Method", "code_challenge_method must be S256", r.URL.Path)
		return
	}

	codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
	if codeChallenge == "" {
		writeProblem(w, http.StatusBadRequest, "Missing PKCE Challenge", "code_challenge is required", r.URL.Path)
		return
	}

	ar, err := adapter.Provider().NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid OAuth Request", err.Error(), r.URL.Path)
		return
	}

	client, err := adapter.Store().GetClient(r.Context(), ar.GetClient().GetID())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Client Not Found", "OAuth client is invalid or disabled", r.URL.Path)
		return
	}

	requestedScopes := make([]string, 0)
	for _, sc := range ar.GetRequestedScopes() {
		requestedScopes = append(requestedScopes, sc)
	}

	consentToken, err := adapter.GenerateConsentToken(
		claims.Subject,
		client.GetID(),
		ar.GetRequestForm().Get("redirect_uri"),
		requestedScopes,
		ar.GetRequestForm().Get("state"),
		codeChallenge,
		codeChallengeMethod,
	)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "Internal Error", "Failed to generate consent token", r.URL.Path)
		return
	}

	response := map[string]any{
		"client_name":      client.GetID(),
		"requested_scopes": requestedScopes,
		"consent_token":    consentToken,
	}
	writeJSON(w, http.StatusOK, response)
}

// handleOAuthAuthorizePost processes consent submission and issues the authorization code to the redirect URI.
func handleOAuthAuthorizePost(w http.ResponseWriter, r *http.Request, adapter *oauth.OAuthAdapter) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
	var body struct {
		ConsentToken string `json:"consent_token"`
		Approved     *bool  `json:"approved"`
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed Request", "Failed to read body", r.URL.Path)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed JSON", "Request body must be valid JSON", r.URL.Path)
			return
		}
	} else {
		parsedForm, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed Form", "Invalid form body", r.URL.Path)
			return
		}
		body.ConsentToken = parsedForm.Get("consent_token")
		approvedVal := parsedForm.Get("approved")
		if approvedVal == "true" || approvedVal == "1" {
			t := true
			body.Approved = &t
		} else if approvedVal != "" {
			f := false
			body.Approved = &f
		}
	}

	if body.ConsentToken == "" {
		writeProblem(w, http.StatusBadRequest, "Validation Error", "consent_token is required", r.URL.Path)
		return
	}

	claims, err := adapter.ValidateConsentToken(body.ConsentToken)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid Consent Token", err.Error(), r.URL.Path)
		return
	}

	if err := adapter.Store().ConsumeConsentID(r.Context(), claims.ConsentID); err != nil {
		writeProblem(w, http.StatusConflict, "Consent Consumed", err.Error(), r.URL.Path)
		return
	}

	if body.Approved == nil || !*body.Approved {
		writeProblem(w, http.StatusForbidden, "Consent Denied", "End-user declined or did not grant authorization consent", r.URL.Path)
		return
	}

	// Build simulated authorize request from validated consent claims
	form := url.Values{
		"client_id":             {claims.ClientID},
		"redirect_uri":          {claims.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(claims.Scopes, " ")},
		"state":                 {claims.State},
		"code_challenge":        {claims.CodeChallenge},
		"code_challenge_method": {claims.CodeChallengeMethod},
	}

	simulatedReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "/v1/oauth/authorize?"+form.Encode(), nil)
	simulatedReq.Form = form

	ar, err := adapter.Provider().NewAuthorizeRequest(r.Context(), simulatedReq)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid Request", err.Error(), r.URL.Path)
		return
	}

	session := adapter.NewSession(claims.UserID)
	for _, sc := range claims.Scopes {
		ar.GrantScope(sc)
	}

	resp, err := adapter.Provider().NewAuthorizeResponse(r.Context(), ar, session)
	if err != nil {
		detail := err.Error()
		if rfcErr, ok := err.(*fosite.RFC6749Error); ok {
			detail = rfcErr.Error() + ": " + rfcErr.HintField + " - " + rfcErr.DebugField
		}
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error", "Failed to issue authorization code: "+detail, r.URL.Path)
		return
	}

	adapter.Provider().WriteAuthorizeResponse(r.Context(), w, ar, resp)
}

// handleOAuthToken exchanges a single-use authorization code with S256 PKCE verification for access tokens.
func handleOAuthToken(adapter *oauth.OAuthAdapter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST is required", r.URL.Path)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "Malformed Request", "Failed to read request body", r.URL.Path)
			return
		}

		// Support both application/json and application/x-www-form-urlencoded
		contentType := r.Header.Get("Content-Type")
		form := make(url.Values)

		if strings.Contains(contentType, "application/json") {
			var jsonMap map[string]string
			if err := json.Unmarshal(bodyBytes, &jsonMap); err == nil {
				for k, v := range jsonMap {
					form.Set(k, v)
				}
			}
		} else {
			parsedForm, err := url.ParseQuery(string(bodyBytes))
			if err == nil {
				form = parsedForm
			}
		}

		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.Form = form
		r.PostForm = form

		session := &fosite.DefaultSession{}
		accessRequest, err := adapter.Provider().NewAccessRequest(r.Context(), r, session)
		if err != nil {
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "invalid_grant",
				"error_description": err.Error(),
			})
			return
		}

		accessResponse, err := adapter.Provider().NewAccessResponse(r.Context(), accessRequest)
		if err != nil {
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "invalid_grant",
				"error_description": err.Error(),
			})
			return
		}

		adapter.Provider().WriteAccessResponse(r.Context(), w, accessRequest, accessResponse)
	}
}
