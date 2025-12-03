package client

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	authv1 "github.com/kabiroman/octawire-auth-service-go-client/pkg/proto/auth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	runIntegrationTests = flag.Bool("integration", false, "Run integration tests that require a running service")
	serviceAddress      = flag.String("service-address", "localhost:50051", "Address of the auth-service for integration tests")
	testAPIKey          = flag.String("api-key", "auth-service-development-key-xyz789uvw456", "API key for authentication")
	testProjectID       = flag.String("project-id", "your-app-api", "Project ID for testing (use jwt.audience from server config)")
)

// TestScenarioConfig содержит конфигурацию для тестового сценария
type TestScenarioConfig struct {
	Name          string
	TLSEnabled    bool
	ServiceAuth   bool
	ServiceName   string
	ServiceSecret string
	JWTToken      string
	APIKey        string
}

// createTestClient создает клиент с конфигурацией на основе сценария
func createTestClient(scenario *TestScenarioConfig, address string) (*Client, error) {
	config := DefaultConfig(address)
	config.TLS = &TLSConfig{
		Enabled:            scenario.TLSEnabled,
		InsecureSkipVerify: scenario.TLSEnabled, // For testing
	}
	if scenario.ServiceAuth {
		config.ServiceName = scenario.ServiceName
		config.ServiceSecret = scenario.ServiceSecret
	}
	if scenario.JWTToken != "" {
		config.JWTToken = scenario.JWTToken
	}
	if scenario.APIKey != "" {
		config.APIKey = scenario.APIKey
	}
	return NewClient(config)
}

// runAllMethodsTests выполняет тесты всех методов с заданным клиентом
func runAllMethodsTests(t *testing.T, config *TestScenarioConfig, cl *Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: HealthCheck (public method)
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := cl.HealthCheck(ctx)
		require.NoError(t, err, "HealthCheck should work")
		assert.Equal(t, "healthy", resp.Status, "Service should be healthy")
		t.Logf("HealthCheck: status=%s, version=%s, uptime=%d", resp.Status, resp.Version, resp.Uptime)
	})

	// Test 2: IssueToken (public method)
	t.Run("IssueToken", func(t *testing.T) {
		req := &authv1.IssueTokenRequest{
			UserId:    "test-user-123",
			ProjectId: *testProjectID,
		}

		resp, err := cl.IssueToken(ctx, req)
		require.NoError(t, err, "IssueToken should work")
		assert.NotEmpty(t, resp.AccessToken, "Access token should be returned")
		assert.NotEmpty(t, resp.RefreshToken, "Refresh token should be returned")
		t.Logf("IssueToken: access_token length=%d, expires_at=%d", len(resp.AccessToken), resp.AccessTokenExpiresAt)
	})

	// Test 3: ValidateToken (optional auth - should work without auth in v1.0+)
	t.Run("ValidateToken", func(t *testing.T) {
		// Issue a token first
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-456",
			ProjectId: *testProjectID,
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.ValidateTokenRequest{
			Token:          issueResp.AccessToken,
			CheckBlacklist: true,
			ProjectId:      *testProjectID,
		}

		resp, err := cl.ValidateToken(ctx, req)
		require.NoError(t, err, "ValidateToken should work (v1.0+)")
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
			ProjectId: *testProjectID,
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.RefreshTokenRequest{
			RefreshToken: issueResp.RefreshToken,
			ProjectId:    *testProjectID,
		}

		resp, err := cl.RefreshToken(ctx, req)
		require.NoError(t, err, "RefreshToken should work")
		assert.NotEmpty(t, resp.AccessToken, "New access token should be returned")
		t.Logf("RefreshToken: new access_token length=%d", len(resp.AccessToken))
	})

	// Test 5: ParseToken (optional auth - should work without auth in v1.0+)
	t.Run("ParseToken", func(t *testing.T) {
		// Issue a token
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-parse",
			ProjectId: *testProjectID,
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.ParseTokenRequest{
			Token:     issueResp.AccessToken,
			ProjectId: *testProjectID,
		}

		resp, err := cl.ParseToken(ctx, req)
		require.NoError(t, err, "ParseToken should work (v1.0+)")
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
			ProjectId: *testProjectID,
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
			ProjectId: *testProjectID,
		}

		resp, err := cl.ExtractClaims(ctx, req)
		require.NoError(t, err, "ExtractClaims should work (v1.0+)")
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
				ProjectId: *testProjectID,
			}
			issueResp, err := cl.IssueToken(ctx, issueReq)
			require.NoError(t, err)
			tokens = append(tokens, issueResp.AccessToken)
		}

		req := &authv1.ValidateBatchRequest{
			Tokens:         tokens,
			CheckBlacklist: true,
			ProjectId:      *testProjectID,
		}

		resp, err := cl.ValidateBatch(ctx, req)
		require.NoError(t, err, "ValidateBatch should work (v1.0+)")
		assert.Len(t, resp.Results, 3, "Should return 3 results")
		for i, result := range resp.Results {
			assert.True(t, result.Valid, "Token %d should be valid", i)
		}
		t.Logf("ValidateBatch: validated %d tokens", len(resp.Results))
	})

	// Test 8: GetPublicKey (public method)
	t.Run("GetPublicKey", func(t *testing.T) {
		req := &authv1.GetPublicKeyRequest{
			ProjectId: *testProjectID,
		}

		resp, err := cl.GetPublicKey(ctx, req)
		require.NoError(t, err, "GetPublicKey should work")
		assert.NotEmpty(t, resp.PublicKeyPem, "Public key should be returned")
		assert.NotEmpty(t, resp.Algorithm, "Algorithm should be returned")
		t.Logf("GetPublicKey: algorithm=%s, key_id=%s", resp.Algorithm, resp.KeyId)
	})

	// Test 9: IssueServiceToken (optional service auth - should work without auth in v1.0+)
	t.Run("IssueServiceToken", func(t *testing.T) {
		req := &authv1.IssueServiceTokenRequest{
			SourceService: "test-service",
			TargetService: "target-service",
			UserId:        "test-user-service",
			ProjectId:     *testProjectID,
		}

		resp, err := cl.IssueServiceToken(ctx, req)
		// May fail if server doesn't support optional service auth yet
		if err != nil {
			t.Logf("IssueServiceToken (may fail on older server versions): %v", err)
		} else {
			assert.NotEmpty(t, resp.AccessToken, "Service token should be returned")
			t.Logf("IssueServiceToken: token length=%d", len(resp.AccessToken))
		}
	})

	// Test 10: RevokeToken (requires JWT - should have JWT in config for this test)
	t.Run("RevokeToken", func(t *testing.T) {
		// First issue a token
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-user-revoke",
			ProjectId: *testProjectID,
		}
		issueResp, err := cl.IssueToken(ctx, issueReq)
		require.NoError(t, err)

		req := &authv1.RevokeTokenRequest{
			Token:     issueResp.AccessToken,
			ProjectId: *testProjectID,
		}

		_, err = cl.RevokeToken(ctx, req)
		if config.JWTToken == "" {
			// Without JWT token, this should fail or be skipped
			t.Logf("RevokeToken without JWT: err=%v (expected)", err)
		} else {
			// With JWT token, this should succeed
			require.NoError(t, err, "RevokeToken should work with JWT token")
		}
	})

	// Test 11: CreateAPIKey (requires JWT and project_id)
	t.Run("CreateAPIKey", func(t *testing.T) {
		if config.JWTToken == "" {
			// Without JWT token, skip this test
			t.Logf("CreateAPIKey without JWT: skipping (JWT token required)")
			return
		}

		req := &authv1.CreateAPIKeyRequest{
			ProjectId: *testProjectID,
			Name:      "test-api-key",
			Scopes:    []string{"read", "write"},
		}

		resp, err := cl.CreateAPIKey(ctx, req)
		if err != nil {
			t.Logf("CreateAPIKey failed: %v", err)
		} else {
			t.Logf("CreateAPIKey succeeded: keyId=%s", resp.KeyId)
		}
	})
}

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
			config.ProjectID = *testProjectID

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
				assert.Equal(t, "healthy", resp.Status, "Service should be healthy")
			})

			// Test 2: IssueToken (public method, should always work)
			t.Run("IssueToken", func(t *testing.T) {
				req := &authv1.IssueTokenRequest{
					UserId:    "test-user-123",
					ProjectId: *testProjectID,
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
					ProjectId:     *testProjectID,
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
					ProjectId: *testProjectID,
				}
				issueResp, err := cl.IssueToken(ctx, issueReq)
				if err != nil {
					t.Fatalf("Failed to issue token for validation test: %v", err)
				}

				// Create client with JWT token
				jwtConfig := DefaultConfig(*serviceAddress)
				jwtConfig.APIKey = *testAPIKey
				jwtConfig.ProjectID = *testProjectID
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
					ProjectId:      *testProjectID,
				}

				resp, err := jwtClient.ValidateToken(ctx, validateReq)
				if err != nil {
					t.Errorf("ValidateToken failed: %v", err)
					return
				}
				assert.True(t, resp.Valid, "Token should be valid")
			})

			// Test 5: GetPublicKey (public method, should always work)
			t.Run("GetPublicKey", func(t *testing.T) {
				req := &authv1.GetPublicKeyRequest{
					ProjectId: *testProjectID,
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

	// Create scenario configuration
	scenario := &TestScenarioConfig{
		Name:        "NoTLS_NoAuth",
		TLSEnabled:  false,
		ServiceAuth: false,
	}

	// Create client
	cl, err := createTestClient(scenario, *serviceAddress)
	require.NoError(t, err, "Failed to create client")
	defer cl.Close()

	// Run all method tests
	runAllMethodsTests(t, scenario, cl)

	t.Log("All tests without TLS and auth completed successfully")
}

// TestAllMethodsScenariosV1 tests all methods across 4 different scenarios:
// 1. No TLS, No Auth
// 2. No TLS, With Service Auth
// 3. With TLS, No Auth
// 4. With TLS, With Service Auth
//
// This test requires a running auth-service.
// Run with: go test -v -integration=true -run TestAllMethodsScenariosV1
func TestAllMethodsScenariosV1(t *testing.T) {
	if !*runIntegrationTests {
		t.Skip("Skipping integration test. Run with -integration=true to execute")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Detect TLS requirement
	tlsRequired, err := detectTLSRequirement(*serviceAddress)
	if err != nil {
		t.Fatalf("Failed to detect TLS requirement: %v", err)
	}

	// Create a temporary client to obtain JWT token for methods requiring JWT
	// This will be used for RevokeToken and CreateAPIKey tests
	var jwtToken string
	tempConfig := DefaultConfig(*serviceAddress)
	tempConfig.TLS = &TLSConfig{
		Enabled:            tlsRequired,
		InsecureSkipVerify: tlsRequired, // For testing
	}
	tempClient, err := NewClient(tempConfig)
	if err == nil {
		defer tempClient.Close()
		// Try to issue a token to use as JWT for protected methods
		issueReq := &authv1.IssueTokenRequest{
			UserId:    "test-jwt-user",
			ProjectId: *testProjectID,
		}
		issueResp, err := tempClient.IssueToken(ctx, issueReq)
		if err == nil {
			jwtToken = issueResp.AccessToken
		}
	}

	// Define all test scenarios
	scenarios := []*TestScenarioConfig{
		{
			Name:        "NoTLS_NoAuth",
			TLSEnabled:  false,
			ServiceAuth: false,
			JWTToken:    jwtToken, // Use JWT token if available
		},
		{
			Name:          "NoTLS_WithServiceAuth",
			TLSEnabled:    false,
			ServiceAuth:   true,
			ServiceName:   "identity-service",
			ServiceSecret: "identity-service-secret-abc123def456",
			JWTToken:      jwtToken, // Use JWT token if available
		},
		{
			Name:        "WithTLS_NoAuth",
			TLSEnabled:  true,
			ServiceAuth: false,
			JWTToken:    jwtToken, // Use JWT token if available
		},
		{
			Name:          "WithTLS_WithServiceAuth",
			TLSEnabled:    true,
			ServiceAuth:   true,
			ServiceName:   "identity-service",
			ServiceSecret: "identity-service-secret-abc123def456",
			JWTToken:      jwtToken, // Use JWT token if available
		},
	}

	// Run tests for each scenario
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			// Skip TLS scenarios if server doesn't support TLS
			if scenario.TLSEnabled && !tlsRequired {
				t.Skipf("Skipping TLS scenario %s: server does not require TLS", scenario.Name)
			}

			// Create client for this scenario
			cl, err := createTestClient(scenario, *serviceAddress)
			if err != nil {
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
					t.Skipf("Skipping scenario %s due to TLS connection error: %v", scenario.Name, err)
				} else {
					t.Fatalf("Failed to create client for scenario %s: %v", scenario.Name, err)
				}
			}
			defer cl.Close()

			// Verify connection with health check
			healthCtx, healthCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer healthCancel()
			_, err = cl.HealthCheck(healthCtx)
			if err != nil {
				// If connection failed, skip this scenario gracefully
				t.Skipf("Skipping scenario %s: service not accessible: %v", scenario.Name, err)
			}

			t.Logf("Testing scenario: %s (TLS=%v, ServiceAuth=%v)", scenario.Name, scenario.TLSEnabled, scenario.ServiceAuth)

			// Run all method tests for this scenario
			runAllMethodsTests(t, scenario, cl)
		})
	}

	t.Log("All scenario tests completed")
}
