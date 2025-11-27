package client

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
)

var (
	runIntegrationTests = flag.Bool("integration", false, "Run integration tests that require a running service")
	serviceAddress      = flag.String("service-address", "localhost:50051", "Address of the auth-service for integration tests")
	testAPIKey          = flag.String("api-key", "DRXpYsOsCNNa94SetlMjnUCvjWbDHW5OrnNlTee_cLc=", "API key for authentication")
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

	// If connection failed, check if it's a TLS-related error
	errStr := strings.ToLower(err.Error())
	if err != nil && (strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") || 
		strings.Contains(errStr, "first record does not look like a tls handshake")) {
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
		name         string
		scenario     string
		serviceAuth  bool
		production   bool
		expectTLS    bool
		serviceName  string
		serviceSecret string
	}{
		{
			name:         "DEV service_auth=false",
			scenario:     "dev-sa-false",
			serviceAuth:  false,
			production:   false,
			expectTLS:    false,
			serviceName:  "",
			serviceSecret: "",
		},
		{
			name:         "DEV service_auth=true",
			scenario:     "dev-sa-true",
			serviceAuth:  true,
			production:   false,
			expectTLS:    false,
			serviceName:  "identity-service",
			serviceSecret: "identity-service-secret-abc123def456",
		},
		{
			name:         "PROD service_auth=false",
			scenario:     "prod-sa-false",
			serviceAuth:  false,
			production:   true,
			expectTLS:    false, // Will be set based on actual server configuration
			serviceName:  "",
			serviceSecret: "",
		},
		{
			name:         "PROD service_auth=true",
			scenario:     "prod-sa-true",
			serviceAuth:  true,
			production:   true,
			expectTLS:    false, // Will be set based on actual server configuration
			serviceName:  "identity-service",
			serviceSecret: "identity-service-secret-abc123def456",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Create client configuration
			config := DefaultConfig(*serviceAddress)
			config.APIKey = *testAPIKey
			config.ProjectID = "default-project-id"

			// Configure service authentication
			if scenario.serviceAuth {
				config.ServiceName = scenario.serviceName
				config.ServiceSecret = scenario.serviceSecret
			}

			// Configure TLS based on actual server requirement (not hardcoded for PROD)
			if tlsRequired {
				config.TLS = &TLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true, // For testing only
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
					UserId: "test-user-123",
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
					UserId: "test-user-123",
				}
				issueResp, err := cl.IssueToken(ctx, issueReq)
				if err != nil {
					t.Fatalf("Failed to issue token for validation test: %v", err)
				}

				// Create client with JWT token
				jwtConfig := DefaultConfig(*serviceAddress)
				jwtConfig.APIKey = *testAPIKey
				jwtConfig.ProjectID = "default-project-id"
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
					Token:         issueResp.AccessToken,
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
				// Try with project_id first
				req := &authv1.GetPublicKeyRequest{
					ProjectId: "default-project-id",
				}
				resp, err := cl.GetPublicKey(ctx, req)
				
				// If fails with "project not found", retry without project_id (legacy mode)
				if err != nil {
					errStr := strings.ToLower(err.Error())
					if strings.Contains(errStr, "project not found") {
						t.Logf("Project not found, retrying without project_id (legacy mode)")
						req = &authv1.GetPublicKeyRequest{
							ProjectId: "", // Empty for legacy single-project mode
						}
						resp, err = cl.GetPublicKey(ctx, req)
					}
				}
				
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

