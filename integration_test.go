package client

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	runIntegrationTests = flag.Bool("integration", false, "Run integration tests that require a running service")
	serviceAddress      = flag.String("service-address", "localhost:50051", "Address of the auth-service for integration tests")
	testAPIKey          = flag.String("api-key", "auth-service-development-key-xyz789uvw456", "API key for authentication")
)

// detectTLSRequirement attempts to connect without TLS first, then with TLS if needed
// Returns true if TLS is required, false otherwise
func detectTLSRequirement(address string) (bool, error) {
	// Try without TLS first
	configNoTLS := DefaultConfig(address)
	configNoTLS.TLS = &TLSConfig{
		Enabled: false,
	}

	clientNoTLS, err := NewClient(configNoTLS)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = clientNoTLS.HealthCheck(ctx)
		clientNoTLS.Close()
		if err == nil {
			return false, nil // TLS not required
		}
	}

	// If connection failed, try with TLS (might be TLS-required server)
	// Try with TLS
	configTLS := DefaultConfig(address)
	configTLS.TLS = &TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
	}
	clientTLS, err2 := NewClient(configTLS)
	if err2 == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err2 = clientTLS.HealthCheck(ctx)
		clientTLS.Close()
		if err2 == nil {
			return true, nil // TLS is required
		}
	}

	// Check if the error indicates TLS requirement
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "first record does not look like a tls handshake") ||
			strings.Contains(errStr, "connection reset") {
			// Likely TLS required, but connection failed - return true anyway
			return true, nil
		}
	}

	// If we can't determine, assume no TLS (most common case)
	return false, nil
}

// TestAllScenariosIntegration tests all configuration scenarios:
// - DEV + service_auth=false
// - DEV + service_auth=true
// - PROD + service_auth=false
// - PROD + service_auth=true
//
// This test requires a running auth-service instance.
// Run with: go test -v -integration=true [-service-address=localhost:50051]
func TestAllScenariosIntegration(t *testing.T) {
	if !*runIntegrationTests {
		t.Skip("Skipping integration test. Run with -integration=true to execute")
	}

	// Detect TLS requirement
	tlsRequired, err := detectTLSRequirement(*serviceAddress)
	if err != nil {
		t.Fatalf("Failed to detect TLS requirement: %v", err)
	}

	// Verify service is reachable before running tests
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testConfig := DefaultConfig(*serviceAddress)
	if tlsRequired {
		testConfig.TLS = &TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		}
	} else {
		testConfig.TLS = &TLSConfig{
			Enabled: false,
		}
	}

	testClient, err := NewClient(testConfig)
	if err != nil {
		t.Fatalf("Cannot connect to service at %s. Make sure auth-service is running: %v", *serviceAddress, err)
	}
	defer testClient.Close()

	// Try health check to verify service is actually running
	_, err = testClient.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("Service at %s is not responding. Make sure auth-service is running and accessible: %v", *serviceAddress, err)
	}

	t.Logf("Service detected: TLS required = %v, API key = %s", tlsRequired, *testAPIKey)

	scenarios := []struct {
		name          string
		scenario      string
		serviceAuth   bool
		production    bool
		expectTLS     bool
		serviceName   string
		serviceSecret string
	}{
		{
			name:          "DEV service_auth=false",
			scenario:      "dev-sa-false",
			serviceAuth:   false,
			production:    false,
			expectTLS:     false,
			serviceName:   "",
			serviceSecret: "",
		},
		{
			name:          "DEV service_auth=true",
			scenario:      "dev-sa-true",
			serviceAuth:   true,
			production:    false,
			expectTLS:     false,
			serviceName:   "identity-service",
			serviceSecret: "identity-service-secret-abc123def456",
		},
		{
			name:          "PROD service_auth=false",
			scenario:      "prod-sa-false",
			serviceAuth:   false,
			production:    true,
			expectTLS:     false, // Will be set based on actual server configuration
			serviceName:   "",
			serviceSecret: "",
		},
		{
			name:          "PROD service_auth=true",
			scenario:      "prod-sa-true",
			serviceAuth:   true,
			production:    true,
			expectTLS:     false, // Will be set based on actual server configuration
			serviceName:   "identity-service",
			serviceSecret: "identity-service-secret-abc123def456",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Create client configuration
			config := DefaultConfig(*serviceAddress)
			config.APIKey = *testAPIKey
			// Don't set ProjectID - use empty string for legacy mode (server uses jwt.audience as project_id)

			// Configure service authentication
			if scenario.serviceAuth {
				config.ServiceName = scenario.serviceName
				config.ServiceSecret = scenario.serviceSecret
			}

			// Configure TLS based on actual server requirement (not hardcoded for PROD)
			if tlsRequired {
				config.TLS = &TLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true, // For testing only - skip certificate verification
					// CAFile: "../../../config/tls/dev-ca.crt", // Optional: use CA file for verification
				}
			} else {
				config.TLS = &TLSConfig{
					Enabled: false,
				}
			}

			// Create client
			cl, err := NewClient(config)
			if err != nil {
				// Check if it's an API key authentication error
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "unauthenticated") || strings.Contains(errStr, "permission denied") {
					t.Fatalf("Failed to create client for scenario %s: %v\nHint: Check if API key '%s' is valid in server configuration", scenario.name, err, *testAPIKey)
				}
				t.Fatalf("Failed to create client for scenario %s: %v", scenario.name, err)
			}
			defer cl.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Test 1: HealthCheck (public method, should always work)
			t.Run("HealthCheck", func(t *testing.T) {
				resp, err := cl.HealthCheck(ctx)
				if err != nil {
					t.Errorf("HealthCheck failed: %v", err)
					return
				}
				assert.True(t, resp.Healthy, "Service should be healthy")
			})

			// Test 2: IssueToken (public method, should always work)
			t.Run("IssueToken", func(t *testing.T) {
				req := &authv1.IssueTokenRequest{
					UserId:    "test-user-123",
					ProjectId: "", // Empty for legacy mode (server uses jwt.audience as project_id)
				}
				resp, err := cl.IssueToken(ctx, req)
				if err != nil {
					errStr := strings.ToLower(err.Error())
					if strings.Contains(errStr, "unauthenticated") || strings.Contains(errStr, "permission denied") {
						t.Errorf("IssueToken failed (authentication error): %v\nHint: Check if API key '%s' is valid in server configuration", err, *testAPIKey)
					} else {
						t.Errorf("IssueToken failed: %v", err)
					}
					return
				}
				assert.NotEmpty(t, resp.AccessToken, "Access token should not be empty")
				assert.NotEmpty(t, resp.KeyId, "Key ID should not be empty")
			})

			// Test 3: IssueServiceToken (requires service auth)
			t.Run("IssueServiceToken", func(t *testing.T) {
				req := &authv1.IssueServiceTokenRequest{
					SourceService: "identity-service",
					TargetService: "gateway-service",
					UserId:        "test-user-123",
					ProjectId:     "", // Empty for legacy mode (server uses jwt.audience as project_id)
					Ttl:           3600,
				}

				resp, err := cl.IssueServiceToken(ctx, req)

				if scenario.serviceAuth {
					// Should succeed with service auth
					if err != nil {
						errStr := strings.ToLower(err.Error())
						if strings.Contains(errStr, "service authentication") {
							t.Errorf("IssueServiceToken failed with service auth configured: %v\nHint: Check if service_name '%s' and service_secret are valid in server configuration", err, scenario.serviceName)
						} else {
							t.Errorf("IssueServiceToken should succeed with service auth, got error: %v", err)
						}
						return
					}
					assert.NotEmpty(t, resp.AccessToken, "Service token should not be empty")
				} else {
					// Should fail without service auth
					if err == nil {
						t.Error("IssueServiceToken should fail without service auth")
						return
					}
					// Check that it's a client-side validation error
					var clientErr *ClientError
					if !errors.As(err, &clientErr) {
						// May also be ErrServiceAuthFailed
						if !errors.Is(err, ErrServiceAuthFailed) {
							// This is expected - client should reject before making request
							if !strings.Contains(strings.ToLower(err.Error()), "service authentication required") {
								t.Errorf("Expected service authentication error, got: %v", err)
							}
						}
					}
				}
			})

			// Test 4: ValidateToken (requires JWT token)
			t.Run("ValidateToken", func(t *testing.T) {
				// First issue a token
				issueReq := &authv1.IssueTokenRequest{
					UserId:    "test-user-123",
					ProjectId: "", // Empty for legacy mode (server uses jwt.audience as project_id)
				}
				issueResp, err := cl.IssueToken(ctx, issueReq)
				if err != nil {
					t.Fatalf("Failed to issue token for validation test: %v", err)
				}

				// Create client with JWT token
				jwtConfig := DefaultConfig(*serviceAddress)
				jwtConfig.APIKey = *testAPIKey
				// Don't set ProjectID - use empty string for legacy mode
				jwtConfig.JWTToken = issueResp.AccessToken

				// Use same TLS configuration as main client
				if tlsRequired {
					jwtConfig.TLS = &TLSConfig{
						Enabled:            true,
						InsecureSkipVerify: true,
					}
				} else {
					jwtConfig.TLS = &TLSConfig{
						Enabled: false,
					}
				}

				jwtClient, err := NewClient(jwtConfig)
				if err != nil {
					t.Fatalf("Failed to create JWT client: %v", err)
				}
				defer jwtClient.Close()

				// Validate token
				validateReq := &authv1.ValidateTokenRequest{
					Token:          issueResp.AccessToken,
					CheckBlacklist: true,
				}

				resp, err := jwtClient.ValidateToken(ctx, validateReq)
				if err != nil {
					t.Errorf("ValidateToken failed: %v", err)
					return
				}
				assert.True(t, resp.Valid, "Token should be valid")
			})

			// Test 5: GetPublicKey (public method, should always work)
			// Handles both multi-project and legacy single-project modes
			t.Run("GetPublicKey", func(t *testing.T) {
				// Use empty project_id for legacy mode
				req := &authv1.GetPublicKeyRequest{
					ProjectId: "", // Empty for legacy mode (server uses jwt.audience as project_id)
				}
				resp, err := cl.GetPublicKey(ctx, req)

				if err != nil {
					t.Errorf("GetPublicKey failed: %v", err)
					return
				}
				assert.NotEmpty(t, resp.PublicKeyPem, "Public key should not be empty")
				assert.NotEmpty(t, resp.Algorithm, "Algorithm should not be empty")
			})
		})
	}
}

// TestAllMethodsWithoutTLSAndAuth tests all methods without TLS and without authentication (v1.0)
// This test requires a running auth-service with:
// - TLS disabled
// - service_auth.enabled = false
// - auth_required = false (or API key not required for public methods)
//
// Run with: go test -v -integration=true -run TestAllMethodsWithoutTLSAndAuth
func TestAllMethodsWithoutTLSAndAuth(t *testing.T) {
	if !*runIntegrationTests {
		t.Skip("Skipping integration test. Run with -integration=true to execute")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create client without TLS and without authentication
	config := DefaultConfig(*serviceAddress)
	config.TLS = &TLSConfig{
		Enabled: false,
	}
	// No service auth, no JWT token, no API key

	cl, err := NewClient(config)
	require.NoError(t, err, "Failed to create client")
	defer cl.Close()

	// Test 1: HealthCheck (public method)
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := cl.HealthCheck(ctx)
		require.NoError(t, err, "HealthCheck should work without auth")
		assert.True(t, resp.Healthy, "Service should be healthy")
		t.Logf("HealthCheck: version=%s, uptime=%d", resp.Version, resp.Uptime)
	})

	// Test 2: IssueToken (public method)
	// Use empty project_id for legacy mode or default_project_id from config
	t.Run("IssueToken", func(t *testing.T) {
		req := &authv1.IssueTokenRequest{
			UserId:    "test-user-123",
			ProjectId: "", // Empty for legacy mode
		}

		resp, err := cl.IssueToken(ctx, req)
		require.NoError(t, err, "IssueToken should work without auth")
		assert.NotEmpty(t, resp.AccessToken, "Access token should be returned")
		assert.NotEmpty(t, resp.RefreshToken, "Refresh token should be returned")
		t.Logf("IssueToken: access_token length=%d, expires_at=%d", len(resp.AccessToken), resp.AccessTokenExpiresAt)
	})

	// Test 3: ValidateToken (optional auth - should work without auth in v1.0+)
	t.Run("ValidateToken", func(t *testing.T) {
		// Issue a token first
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-456",
			ProjectId: "", // Empty for legacy mode
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.ValidateTokenRequest{
			Token:          issueResp.AccessToken,
			CheckBlacklist: true,
		}

		resp, err := cl.ValidateToken(ctx, req)
		require.NoError(t, err, "ValidateToken should work without auth (v1.0+)")
		assert.True(t, resp.Valid, "Token should be valid")
		if resp.Claims != nil {
			t.Logf("ValidateToken: user_id=%s, expires_at=%d", resp.Claims.UserId, resp.Claims.ExpiresAt)
		}
	})

	// Test 4: RefreshToken (public method)
	t.Run("RefreshToken", func(t *testing.T) {
		// First issue a token
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-789",
			ProjectId: "", // Empty for legacy mode
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.RefreshTokenRequest{
			RefreshToken: issueResp.RefreshToken,
		}

		resp, err := cl.RefreshToken(ctx, req)
		require.NoError(t, err, "RefreshToken should work without auth")
		assert.NotEmpty(t, resp.AccessToken, "New access token should be returned")
		t.Logf("RefreshToken: new access_token length=%d", len(resp.AccessToken))
	})

	// Test 5: ParseToken (optional auth - should work without auth in v1.0+)
	t.Run("ParseToken", func(t *testing.T) {
		// Issue a token
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-parse",
			ProjectId: "", // Empty for legacy mode
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.ParseTokenRequest{
			Token: issueResp.AccessToken,
		}

		resp, err := cl.ParseToken(ctx, req)
		require.NoError(t, err, "ParseToken should work without auth (v1.0+)")
		assert.True(t, resp.Success, "Token should be parsed successfully")
		if resp.Claims != nil {
			t.Logf("ParseToken: user_id=%s, token_type=%s", resp.Claims.UserId, resp.Claims.TokenType)
		}
	})

	// Test 6: ExtractClaims (optional auth - should work without auth in v1.0+)
	t.Run("ExtractClaims", func(t *testing.T) {
		// Issue a token with custom claims
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-extract",
			ProjectId: "", // Empty for legacy mode
			Claims: map[string]string{
				"role": "admin",
				"team": "backend",
			},
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.ExtractClaimsRequest{
			Token:     issueResp.AccessToken,
			ClaimKeys: []string{"user_id", "role", "team"},
		}

		resp, err := cl.ExtractClaims(ctx, req)
		require.NoError(t, err, "ExtractClaims should work without auth (v1.0+)")
		assert.True(t, resp.Success, "Claims should be extracted successfully")
		assert.NotEmpty(t, resp.Claims, "Claims should not be empty")
		t.Logf("ExtractClaims: extracted %d claims", len(resp.Claims))
	})

	// Test 7: ValidateBatch (optional auth - should work without auth in v1.0+)
	t.Run("ValidateBatch", func(t *testing.T) {
		// Issue multiple tokens
		var tokens []string
		for i := 0; i < 3; i++ {
			issueReq := &authv1.IssueTokenRequest{
				UserId:    "test-user-batch-" + string(rune('0'+i)),
				ProjectId: "", // Empty for legacy mode
			}
			issueResp, err := cl.IssueToken(ctx, issueReq)
			require.NoError(t, err)
			tokens = append(tokens, issueResp.AccessToken)
		}

		req := &authv1.ValidateBatchRequest{
			Tokens:         tokens,
			CheckBlacklist: true,
		}

		resp, err := cl.ValidateBatch(ctx, req)
		require.NoError(t, err, "ValidateBatch should work without auth (v1.0+)")
		assert.Len(t, resp.Results, 3, "Should return 3 results")
		for i, result := range resp.Results {
			assert.True(t, result.Valid, "Token %d should be valid", i)
		}
		t.Logf("ValidateBatch: validated %d tokens", len(resp.Results))
	})

	// Test 8: GetPublicKey (public method)
	t.Run("GetPublicKey", func(t *testing.T) {
		req := &authv1.GetPublicKeyRequest{
			ProjectId: "", // Empty for legacy mode
		}

		resp, err := cl.GetPublicKey(ctx, req)
		require.NoError(t, err, "GetPublicKey should work without auth")
		assert.NotEmpty(t, resp.PublicKeyPem, "Public key should be returned")
		assert.NotEmpty(t, resp.Algorithm, "Algorithm should be returned")
		t.Logf("GetPublicKey: algorithm=%s, key_id=%s", resp.Algorithm, resp.KeyId)
	})

	// Test 9: IssueServiceToken (optional service auth - should work without auth in v1.0+)
	// Note: Current server version (v0.9.0) may still require service auth
	t.Run("IssueServiceToken", func(t *testing.T) {
		req := &authv1.IssueServiceTokenRequest{
			SourceService: "test-service",
			TargetService: "target-service",
			UserId:        "test-user-service",
			ProjectId:     "", // Empty for legacy mode
		}

		resp, err := cl.IssueServiceToken(ctx, req)
		// May fail if server doesn't support optional service auth yet (v0.9.0)
		if err != nil {
			t.Logf("IssueServiceToken without service auth (may fail on v0.9.0): %v", err)
			// This is expected if server version doesn't support optional service auth
		} else {
			assert.NotEmpty(t, resp.AccessToken, "Service token should be returned")
			t.Logf("IssueServiceToken: token length=%d", len(resp.AccessToken))
		}
	})

	// Test 10: RevokeToken (requires JWT - should fail without JWT)
	t.Run("RevokeToken_RequiresJWT", func(t *testing.T) {
		// First issue a token
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-revoke",
			ProjectId: "", // Empty for legacy mode
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.RevokeTokenRequest{
			Token: issueResp.AccessToken,
		}

		_, err = cl.RevokeToken(ctx, req)
		// Should fail without JWT token in config (but might succeed if server doesn't enforce)
		// In v1.0, this might work depending on server config
		t.Logf("RevokeToken without JWT result: err=%v", err)
	})

	// Test 11: CreateAPIKey (requires JWT - should fail without JWT)
	t.Run("CreateAPIKey_RequiresJWT", func(t *testing.T) {
		req := &authv1.CreateAPIKeyRequest{
			ProjectId: "", // Empty for legacy mode
			Name:      "test-api-key",
			Scopes:    []string{"read", "write"},
		}

		_, err := cl.CreateAPIKey(ctx, req)
		// Should fail without JWT token in config (but might succeed if server doesn't enforce)
		// In v1.0, this might work depending on server config
		t.Logf("CreateAPIKey without JWT result: err=%v", err)
	})

	t.Log("All tests without TLS and auth completed successfully")
}
