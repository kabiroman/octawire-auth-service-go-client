package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kabiroman/octawire-auth-service-go-client"
	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
)

type TestResult struct {
	Name    string
	Passed  bool
	Error   error
	Message string
}

type TestSuite struct {
	Scenario string
	Results  []TestResult
	Client   *client.Client
}

func NewTestSuite(scenario string) *TestSuite {
	return &TestSuite{
		Scenario: scenario,
		Results:  make([]TestResult, 0),
	}
}

func newClientWithJWT(token string) (*client.Client, error) {
	cfg := client.DefaultConfig("localhost:50051")
	cfg.APIKey = testAPIKey
	cfg.ProjectID = "default-project-id"
	if token != "" {
		cfg.JWTToken = token
	}
	return client.NewClient(cfg)
}

func (ts *TestSuite) AddResult(name string, passed bool, err error, message string) {
	ts.Results = append(ts.Results, TestResult{
		Name:    name,
		Passed:  passed,
		Error:   err,
		Message: message,
	})
}

func (ts *TestSuite) PrintResults() {
	fmt.Printf("\n=== Test Results for Scenario: %s ===\n", ts.Scenario)
	passed := 0
	failed := 0

	for _, result := range ts.Results {
		if result.Passed {
			fmt.Printf("✅ %s: PASSED", result.Name)
			if result.Message != "" {
				fmt.Printf(" - %s", result.Message)
			}
			fmt.Println()
			passed++
		} else {
			fmt.Printf("❌ %s: FAILED", result.Name)
			if result.Message != "" {
				fmt.Printf(" - %s", result.Message)
			}
			if result.Error != nil {
				fmt.Printf(" (error: %v)", result.Error)
			}
			fmt.Println()
			failed++
		}
	}

	fmt.Printf("\nSummary: %d passed, %d failed\n", passed, failed)
}

const testAPIKey = "auth-service-development-key-xyz789uvw456"

func main() {
	scenario := flag.String("scenario", "dev-sa-true", "Test scenario: dev-sa-false, dev-sa-true, prod-sa-false, prod-sa-true")
	flag.Parse()

	ts := NewTestSuite(*scenario)
	ctx := context.Background()

	// Create client configuration based on scenario
	config := client.DefaultConfig("localhost:50051")
	config.APIKey = testAPIKey
	config.ProjectID = "default-project-id"

	// Configure authentication and TLS based on scenario
	switch *scenario {
	case "dev-sa-true", "prod-sa-true":
		config.ServiceName = "identity-service"
		config.ServiceSecret = "identity-service-secret-abc123def456"
	}

	// Configure TLS for production scenarios
	if *scenario == "prod-sa-false" || *scenario == "prod-sa-true" {
		// In production, TLS is recommended/required
		// For testing, we can use InsecureSkipVerify if certificates are not available
		config.TLS = &client.TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true, // Only for testing - skip certificate verification
		}
	}

	// Create client
	cl, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer cl.Close()
	ts.Client = cl

	fmt.Printf("Running tests for scenario: %s\n", *scenario)
	fmt.Printf("Service Auth: %v\n", config.ServiceName != "" && config.ServiceSecret != "")

	// Test 1: Public Methods - IssueToken
	ts.testIssueToken(ctx)

	// Test 2: Public Methods - RefreshToken
	ts.testRefreshToken(ctx)

	// Test 3: Public Methods - GetPublicKey
	ts.testGetPublicKey(ctx)

	// Test 4: Public Methods - HealthCheck
	ts.testHealthCheck(ctx)

	// Test 5: Service Auth - IssueServiceToken without auth
	ts.testIssueServiceTokenWithoutAuth(ctx)

	// Test 6: Service Auth - IssueServiceToken with auth
	ts.testIssueServiceTokenWithAuth(ctx)

	// Test 7: Service Auth - IssueServiceToken with invalid auth
	ts.testIssueServiceTokenWithInvalidAuth(ctx)

	// Test 8: JWT Auth - ValidateToken without JWT
	ts.testValidateTokenWithoutJWT(ctx)

	// Test 9: JWT Auth - ValidateToken with JWT
	ts.testValidateTokenWithJWT(ctx)

	// Test 10: JWT Auth - ParseToken with JWT
	ts.testParseTokenWithJWT(ctx)

	// Test 11: JWT Auth - ExtractClaims with JWT
	ts.testExtractClaimsWithJWT(ctx)

	// Test 12: JWT Auth - RevokeToken with JWT
	ts.testRevokeTokenWithJWT(ctx)

	// Test 13: JWT Auth - ValidateBatch with JWT
	ts.testValidateBatchWithJWT(ctx)

	// Test 14: APIKeyService - CreateAPIKey with JWT
	ts.testCreateAPIKeyWithJWT(ctx)

	// Test 15: APIKeyService - ValidateAPIKey with JWT
	ts.testValidateAPIKeyWithJWT(ctx)

	// Test 16: APIKeyService - ListAPIKeys with JWT
	ts.testListAPIKeysWithJWT(ctx)

	// Test 17: Error Handling - ErrServiceAuthFailed
	ts.testErrorHandling(ctx)

	// Print results
	ts.PrintResults()

	// Exit with error code if any tests failed
	for _, result := range ts.Results {
		if !result.Passed {
			os.Exit(1)
		}
	}
}

func (ts *TestSuite) testIssueToken(ctx context.Context) {
	req := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
		Claims: map[string]string{
			"role": "admin",
		},
		AccessTokenTtl:  3600,
		RefreshTokenTtl: 86400,
	}

	resp, err := ts.Client.IssueToken(ctx, req)
	if err != nil {
		ts.AddResult("IssueToken", false, err, "Failed to issue token")
		return
	}

	if resp.AccessToken == "" {
		ts.AddResult("IssueToken", false, nil, "Access token is empty")
		return
	}

	ts.AddResult("IssueToken", true, nil, fmt.Sprintf("Token issued, key_id: %s", resp.KeyId))
}

func (ts *TestSuite) testRefreshToken(ctx context.Context) {
	// First issue a token
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	issueResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("RefreshToken", false, err, "Failed to issue initial token")
		return
	}

	// Now refresh it
	req := &authv1.RefreshTokenRequest{
		RefreshToken: issueResp.RefreshToken,
		ProjectId:    "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}

	resp, err := ts.Client.RefreshToken(ctx, req)
	if err != nil {
		ts.AddResult("RefreshToken", false, err, "Failed to refresh token")
		return
	}

	if resp.AccessToken == "" {
		ts.AddResult("RefreshToken", false, nil, "New access token is empty")
		return
	}

	ts.AddResult("RefreshToken", true, nil, "Token refreshed successfully")
}

func (ts *TestSuite) testGetPublicKey(ctx context.Context) {
	req := &authv1.GetPublicKeyRequest{
		ProjectId: "default-project-id",
	}

	resp, err := ts.Client.GetPublicKey(ctx, req)
	if err != nil {
		ts.AddResult("GetPublicKey", false, err, "Failed to get public key")
		return
	}

	if resp.PublicKeyPem == "" {
		ts.AddResult("GetPublicKey", false, nil, "Public key is empty")
		return
	}

	ts.AddResult("GetPublicKey", true, nil, fmt.Sprintf("Key retrieved, algorithm: %s", resp.Algorithm))
}

func (ts *TestSuite) testHealthCheck(ctx context.Context) {
	resp, err := ts.Client.HealthCheck(ctx)
	if err != nil {
		ts.AddResult("HealthCheck", false, err, "Failed to check health")
		return
	}

	ts.AddResult("HealthCheck", true, nil, fmt.Sprintf("Service healthy: %v, version: %s", resp.Healthy, resp.Version))
}

func (ts *TestSuite) testIssueServiceTokenWithoutAuth(ctx context.Context) {
	// Create client without service auth
	cl, err := newClientWithJWT("")
	if err != nil {
		ts.AddResult("IssueServiceToken (no auth)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
		TargetService: "gateway-service",
		UserId:        "test-user-123",
		ProjectId:     "", // Empty - will use default-project-id from metadata (v0.9.3+)
		Ttl:           3600,
	}

	_, err = cl.IssueServiceToken(ctx, req)
	if err != nil {
		// Expected to fail
		var clientErr *client.ClientError
		if errors.As(err, &clientErr) {
			ts.AddResult("IssueServiceToken (no auth)", true, nil, "Correctly failed with client error")
		} else if errors.Is(err, client.ErrServiceAuthFailed) {
			ts.AddResult("IssueServiceToken (no auth)", true, nil, "Correctly failed with ErrServiceAuthFailed")
		} else {
			ts.AddResult("IssueServiceToken (no auth)", true, nil, fmt.Sprintf("Failed as expected: %v", err))
		}
	} else {
		ts.AddResult("IssueServiceToken (no auth)", false, nil, "Should have failed but succeeded")
	}
}

func (ts *TestSuite) testIssueServiceTokenWithAuth(ctx context.Context) {
	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
		TargetService: "gateway-service",
		UserId:        "test-user-123",
		ProjectId:     "", // Empty - will use default-project-id from metadata (v0.9.3+)
		Ttl:           3600,
	}

	resp, err := ts.Client.IssueServiceToken(ctx, req)
	if err != nil {
		ts.AddResult("IssueServiceToken (with auth)", false, err, "Failed to issue service token")
		return
	}

	if resp.AccessToken == "" {
		ts.AddResult("IssueServiceToken (with auth)", false, nil, "Service token is empty")
		return
	}

	ts.AddResult("IssueServiceToken (with auth)", true, nil, "Service token issued successfully")
}

func (ts *TestSuite) testIssueServiceTokenWithInvalidAuth(ctx context.Context) {
	// Create client with invalid service auth
	config := client.DefaultConfig("localhost:50051")
	config.ProjectID = "default-project-id"
	config.ServiceName = "identity-service"
	config.ServiceSecret = "wrong-secret"
	config.APIKey = testAPIKey

	cl, err := client.NewClient(config)
	if err != nil {
		ts.AddResult("IssueServiceToken (invalid auth)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
		TargetService: "gateway-service",
		UserId:        "test-user-123",
		ProjectId:     "", // Empty - will use default-project-id from metadata (v0.9.3+)
		Ttl:           3600,
	}

	_, err = cl.IssueServiceToken(ctx, req)
	if err != nil {
		// Expected to fail
		if errors.Is(err, client.ErrServiceAuthFailed) {
			ts.AddResult("IssueServiceToken (invalid auth)", true, nil, "Correctly failed with ErrServiceAuthFailed")
		} else {
			ts.AddResult("IssueServiceToken (invalid auth)", true, nil, fmt.Sprintf("Failed as expected: %v", err))
		}
	} else {
		ts.AddResult("IssueServiceToken (invalid auth)", false, nil, "Should have failed but succeeded")
	}
}

func (ts *TestSuite) testValidateTokenWithoutJWT(ctx context.Context) {
	// First issue a token
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	issueResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("ValidateToken (no JWT)", false, err, "Failed to issue token")
		return
	}

	// Create client without JWT token
	cl, err := newClientWithJWT("")
	if err != nil {
		ts.AddResult("ValidateToken (no JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.ValidateTokenRequest{
		Token:          issueResp.AccessToken,
		ProjectId:      "", // Empty - will use default-project-id from metadata (v0.9.3+)
		CheckBlacklist: true,
	}

	_, err = cl.ValidateToken(ctx, req)
	if err != nil {
		// Expected to fail
		ts.AddResult("ValidateToken (no JWT)", true, nil, fmt.Sprintf("Correctly failed: %v", err))
	} else {
		ts.AddResult("ValidateToken (no JWT)", false, nil, "Should have failed but succeeded")
	}
}

func (ts *TestSuite) testValidateTokenWithJWT(ctx context.Context) {
	// First issue a token to use as JWT
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("ValidateToken (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(jwtTokenResp.AccessToken)
	if err != nil {
		ts.AddResult("ValidateToken (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.ValidateTokenRequest{
		Token:          jwtTokenResp.AccessToken,
		ProjectId:      "", // Empty - will use default-project-id from metadata (v0.9.3+)
		CheckBlacklist: true,
	}

	resp, err := cl.ValidateToken(ctx, req)
	if err != nil {
		ts.AddResult("ValidateToken (with JWT)", false, err, "Failed to validate token")
		return
	}

	if !resp.Valid {
		ts.AddResult("ValidateToken (with JWT)", false, nil, fmt.Sprintf("Token invalid: %s", resp.Error))
		return
	}

	ts.AddResult("ValidateToken (with JWT)", true, nil, "Token validated successfully")
}

func (ts *TestSuite) testParseTokenWithJWT(ctx context.Context) {
	// Issue a token to use as JWT
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("ParseToken (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(jwtTokenResp.AccessToken)
	if err != nil {
		ts.AddResult("ParseToken (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.ParseTokenRequest{
		Token:     jwtTokenResp.AccessToken,
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}

	resp, err := cl.ParseToken(ctx, req)
	if err != nil {
		ts.AddResult("ParseToken (with JWT)", false, err, "Failed to parse token")
		return
	}

	if !resp.Success {
		ts.AddResult("ParseToken (with JWT)", false, nil, fmt.Sprintf("Parse failed: %s", resp.Error))
		return
	}

	ts.AddResult("ParseToken (with JWT)", true, nil, "Token parsed successfully")
}

func (ts *TestSuite) testExtractClaimsWithJWT(ctx context.Context) {
	// Issue a token to use as JWT
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
		Claims: map[string]string{
			"role": "admin",
		},
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("ExtractClaims (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(jwtTokenResp.AccessToken)
	if err != nil {
		ts.AddResult("ExtractClaims (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.ExtractClaimsRequest{
		Token:     jwtTokenResp.AccessToken,
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
		ClaimKeys: []string{"user_id", "role"},
	}

	resp, err := cl.ExtractClaims(ctx, req)
	if err != nil {
		ts.AddResult("ExtractClaims (with JWT)", false, err, "Failed to extract claims")
		return
	}

	if !resp.Success {
		ts.AddResult("ExtractClaims (with JWT)", false, nil, fmt.Sprintf("Extract failed: %s", resp.Error))
		return
	}

	ts.AddResult("ExtractClaims (with JWT)", true, nil, fmt.Sprintf("Claims extracted: %d", len(resp.Claims)))
}

func (ts *TestSuite) testRevokeTokenWithJWT(ctx context.Context) {
	// Issue a token to use as JWT
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("RevokeToken (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(jwtTokenResp.AccessToken)
	if err != nil {
		ts.AddResult("RevokeToken (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.RevokeTokenRequest{
		Token:     jwtTokenResp.AccessToken,
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
		Ttl:       3600,
	}

	resp, err := cl.RevokeToken(ctx, req)
	if err != nil {
		ts.AddResult("RevokeToken (with JWT)", false, err, "Failed to revoke token")
		return
	}

	if !resp.Success {
		ts.AddResult("RevokeToken (with JWT)", false, nil, fmt.Sprintf("Revoke failed: %s", resp.Error))
		return
	}

	ts.AddResult("RevokeToken (with JWT)", true, nil, "Token revoked successfully")
}

func (ts *TestSuite) testValidateBatchWithJWT(ctx context.Context) {
	// Issue tokens to validate
	issueReq1 := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	token1Resp, err := ts.Client.IssueToken(ctx, issueReq1)
	if err != nil {
		ts.AddResult("ValidateBatch (with JWT)", false, err, "Failed to issue token 1")
		return
	}

	issueReq2 := &authv1.IssueTokenRequest{
		UserId:    "test-user-456",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	token2Resp, err := ts.Client.IssueToken(ctx, issueReq2)
	if err != nil {
		ts.AddResult("ValidateBatch (with JWT)", false, err, "Failed to issue token 2")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(token1Resp.AccessToken)
	if err != nil {
		ts.AddResult("ValidateBatch (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.ValidateBatchRequest{
		Tokens:         []string{token1Resp.AccessToken, token2Resp.AccessToken},
		CheckBlacklist: true,
	}

	resp, err := cl.ValidateBatch(ctx, req)
	if err != nil {
		ts.AddResult("ValidateBatch (with JWT)", false, err, "Failed to validate batch")
		return
	}

	if len(resp.Results) != 2 {
		ts.AddResult("ValidateBatch (with JWT)", false, nil, fmt.Sprintf("Expected 2 results, got %d", len(resp.Results)))
		return
	}

	ts.AddResult("ValidateBatch (with JWT)", true, nil, fmt.Sprintf("Batch validated: %d tokens", len(resp.Results)))
}

func (ts *TestSuite) testCreateAPIKeyWithJWT(ctx context.Context) {
	// Issue a token to use as JWT
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("CreateAPIKey (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(jwtTokenResp.AccessToken)
	if err != nil {
		ts.AddResult("CreateAPIKey (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.CreateAPIKeyRequest{
		ProjectId: "default-project-id",
		UserId:    "test-user-123",
		Name:      "Test API Key",
		Scopes:    []string{"read", "write"},
		Ttl:       86400 * 30, // 30 days
	}

	resp, err := cl.CreateAPIKey(ctx, req)
	if err != nil {
		ts.AddResult("CreateAPIKey (with JWT)", false, err, "Failed to create API key")
		return
	}

	if resp.ApiKey == "" {
		ts.AddResult("CreateAPIKey (with JWT)", false, nil, "API key is empty")
		return
	}

	ts.AddResult("CreateAPIKey (with JWT)", true, nil, fmt.Sprintf("API key created: %s", resp.KeyId))
}

func (ts *TestSuite) testValidateAPIKeyWithJWT(ctx context.Context) {
	// First create an API key
	issueReq := &authv1.IssueTokenRequest{
		UserId: "test-user-123",
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("ValidateAPIKey (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	config := client.DefaultConfig("localhost:50051")
	config.ProjectID = "default-project-id"
	config.JWTToken = jwtTokenResp.AccessToken

	cl, err := client.NewClient(config)
	if err != nil {
		ts.AddResult("ValidateAPIKey (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	// Create API key first
	createReq := &authv1.CreateAPIKeyRequest{
		ProjectId: "default-project-id",
		Name:      "Test API Key",
		Scopes:    []string{"read"},
	}
	apiKeyResp, err := cl.CreateAPIKey(ctx, createReq)
	if err != nil {
		ts.AddResult("ValidateAPIKey (with JWT)", false, err, "Failed to create API key for testing")
		return
	}

	// Now validate it
	validateReq := &authv1.ValidateAPIKeyRequest{
		ApiKey:         apiKeyResp.ApiKey,
		RequiredScopes: []string{"read"},
	}

	validateResp, err := cl.ValidateAPIKey(ctx, validateReq)
	if err != nil {
		ts.AddResult("ValidateAPIKey (with JWT)", false, err, "Failed to validate API key")
		return
	}

	if !validateResp.Valid {
		ts.AddResult("ValidateAPIKey (with JWT)", false, nil, fmt.Sprintf("API key invalid: %s", validateResp.Error))
		return
	}

	ts.AddResult("ValidateAPIKey (with JWT)", true, nil, "API key validated successfully")
}

func (ts *TestSuite) testListAPIKeysWithJWT(ctx context.Context) {
	// Issue a token to use as JWT
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "test-user-123",
		ProjectId: "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}
	jwtTokenResp, err := ts.Client.IssueToken(ctx, issueReq)
	if err != nil {
		ts.AddResult("ListAPIKeys (with JWT)", false, err, "Failed to issue JWT token")
		return
	}

	// Create client with JWT token
	cl, err := newClientWithJWT(jwtTokenResp.AccessToken)
	if err != nil {
		ts.AddResult("ListAPIKeys (with JWT)", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.ListAPIKeysRequest{
		ProjectId: "default-project-id",
		Page:      1,
		PageSize:  10,
	}

	resp, err := cl.ListAPIKeys(ctx, req)
	if err != nil {
		ts.AddResult("ListAPIKeys (with JWT)", false, err, "Failed to list API keys")
		return
	}

	ts.AddResult("ListAPIKeys (with JWT)", true, nil, fmt.Sprintf("Listed %d API keys", resp.Total))
}

func (ts *TestSuite) testErrorHandling(ctx context.Context) {
	// Test ErrServiceAuthFailed
	config := client.DefaultConfig("localhost:50051")
	config.APIKey = testAPIKey
	config.ServiceName = "identity-service"
	config.ServiceSecret = "wrong-secret"

	cl, err := client.NewClient(config)
	if err != nil {
		ts.AddResult("Error Handling", false, err, "Failed to create client")
		return
	}
	defer cl.Close()

	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
		ProjectId:     "", // Empty - will use default-project-id from metadata (v0.9.3+)
	}

	_, err = cl.IssueServiceToken(ctx, req)
	if err != nil {
		if errors.Is(err, client.ErrServiceAuthFailed) {
			ts.AddResult("Error Handling", true, nil, "ErrServiceAuthFailed correctly returned")
		} else {
			ts.AddResult("Error Handling", true, nil, fmt.Sprintf("Error returned (may be wrapped): %v", err))
		}
	} else {
		ts.AddResult("Error Handling", false, nil, "Should have failed but succeeded")
	}
}
