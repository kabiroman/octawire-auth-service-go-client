package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/kabiroman/octawire-auth-service-go-client/pkg/proto/auth/v1"
)

// MockJWTServiceClient - мок для JWTServiceClient
type MockJWTServiceClient struct {
	mock.Mock
}

func (m *MockJWTServiceClient) IssueToken(ctx context.Context, req *authv1.IssueTokenRequest, opts ...grpc.CallOption) (*authv1.IssueTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.IssueTokenResponse), args.Error(1)
}

func (m *MockJWTServiceClient) IssueServiceToken(ctx context.Context, req *authv1.IssueServiceTokenRequest, opts ...grpc.CallOption) (*authv1.IssueTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.IssueTokenResponse), args.Error(1)
}

func (m *MockJWTServiceClient) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest, opts ...grpc.CallOption) (*authv1.ValidateTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.ValidateTokenResponse), args.Error(1)
}

func (m *MockJWTServiceClient) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest, opts ...grpc.CallOption) (*authv1.RefreshTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.RefreshTokenResponse), args.Error(1)
}

func (m *MockJWTServiceClient) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest, opts ...grpc.CallOption) (*authv1.RevokeTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.RevokeTokenResponse), args.Error(1)
}

func (m *MockJWTServiceClient) ParseToken(ctx context.Context, req *authv1.ParseTokenRequest, opts ...grpc.CallOption) (*authv1.ParseTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.ParseTokenResponse), args.Error(1)
}

func (m *MockJWTServiceClient) ExtractClaims(ctx context.Context, req *authv1.ExtractClaimsRequest, opts ...grpc.CallOption) (*authv1.ExtractClaimsResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.ExtractClaimsResponse), args.Error(1)
}

func (m *MockJWTServiceClient) ValidateBatch(ctx context.Context, req *authv1.ValidateBatchRequest, opts ...grpc.CallOption) (*authv1.ValidateBatchResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.ValidateBatchResponse), args.Error(1)
}

func (m *MockJWTServiceClient) GetPublicKey(ctx context.Context, req *authv1.GetPublicKeyRequest, opts ...grpc.CallOption) (*authv1.GetPublicKeyResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.GetPublicKeyResponse), args.Error(1)
}

func (m *MockJWTServiceClient) HealthCheck(ctx context.Context, req *authv1.HealthCheckRequest, opts ...grpc.CallOption) (*authv1.HealthCheckResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.HealthCheckResponse), args.Error(1)
}

// MockAPIKeyServiceClient - мок для APIKeyServiceClient
type MockAPIKeyServiceClient struct {
	mock.Mock
}

func (m *MockAPIKeyServiceClient) CreateAPIKey(ctx context.Context, req *authv1.CreateAPIKeyRequest, opts ...grpc.CallOption) (*authv1.CreateAPIKeyResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.CreateAPIKeyResponse), args.Error(1)
}

func (m *MockAPIKeyServiceClient) ValidateAPIKey(ctx context.Context, req *authv1.ValidateAPIKeyRequest, opts ...grpc.CallOption) (*authv1.ValidateAPIKeyResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.ValidateAPIKeyResponse), args.Error(1)
}

func (m *MockAPIKeyServiceClient) RevokeAPIKey(ctx context.Context, req *authv1.RevokeAPIKeyRequest, opts ...grpc.CallOption) (*authv1.RevokeAPIKeyResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.RevokeAPIKeyResponse), args.Error(1)
}

func (m *MockAPIKeyServiceClient) ListAPIKeys(ctx context.Context, req *authv1.ListAPIKeysRequest, opts ...grpc.CallOption) (*authv1.ListAPIKeysResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authv1.ListAPIKeysResponse), args.Error(1)
}

// TestErrorHandling тестирует обработку ошибок
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Unavailable error is retryable",
			err:      status.Error(codes.Unavailable, "service unavailable"),
			expected: true,
		},
		{
			name:     "DeadlineExceeded error is retryable",
			err:      status.Error(codes.DeadlineExceeded, "deadline exceeded"),
			expected: true,
		},
		{
			name:     "ResourceExhausted error is retryable",
			err:      status.Error(codes.ResourceExhausted, "resource exhausted"),
			expected: true,
		},
		{
			name:     "InvalidArgument error is not retryable",
			err:      status.Error(codes.InvalidArgument, "invalid argument"),
			expected: false,
		},
		{
			name:     "Non-gRPC error is not retryable",
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestWrapError тестирует обертку ошибок
func TestWrapError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		checkFn func(error) bool
	}{
		{
			name:    "Unavailable error",
			err:     status.Error(codes.Unavailable, "service unavailable"),
			checkFn: func(err error) bool { return errors.Is(err, ErrConnectionFailed) },
		},
		{
			name:    "Rate limit error",
			err:     status.Error(codes.ResourceExhausted, "rate limit exceeded"),
			checkFn: func(err error) bool { return errors.Is(err, ErrRateLimitExceeded) },
		},
		{
			name:    "Non-gRPC error",
			err:     errors.New("some error"),
			checkFn: func(err error) bool { return err != nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapError(tt.err)
			assert.True(t, tt.checkFn(wrapped))
		})
	}
}

// TestKeyCache тестирует кэш ключей
func TestKeyCache(t *testing.T) {
	cache := NewKeyCache(&KeyCacheConfig{
		TTL:     1 * time.Hour,
		MaxSize: 10,
	})

	projectID := "test-project"
	keyID := "key-1"
	keyInfo := &authv1.PublicKeyInfo{
		KeyId:        keyID,
		PublicKeyPem: "test-key",
		Algorithm:    "RS256",
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
		IsPrimary:    true,
	}

	// Тест Set и Get
	cache.Set(projectID, keyInfo, time.Now().Add(1*time.Hour).Unix())
	retrieved, ok := cache.Get(projectID, keyID)
	assert.True(t, ok)
	assert.Equal(t, keyInfo.KeyId, retrieved.KeyId)
	assert.Equal(t, keyInfo.PublicKeyPem, retrieved.PublicKeyPem)

	// Тест GetAllActive
	activeKeys := cache.GetAllActive(projectID)
	assert.Len(t, activeKeys, 1)
	assert.Equal(t, keyID, activeKeys[0].KeyId)

	// Тест Invalidate
	cache.Invalidate(projectID)
	_, ok = cache.Get(projectID, keyID)
	assert.False(t, ok)

	// Тест SetAllActive
	activeKeysList := []*authv1.PublicKeyInfo{
		{KeyId: "key-1", PublicKeyPem: "key1", Algorithm: "RS256", IsPrimary: true},
		{KeyId: "key-2", PublicKeyPem: "key2", Algorithm: "RS256", IsPrimary: false},
	}
	cache.SetAllActive(projectID, activeKeysList, time.Now().Add(1*time.Hour).Unix())
	allActive := cache.GetAllActive(projectID)
	assert.Len(t, allActive, 2)

	// Тест Clear
	cache.Clear()
	allActive = cache.GetAllActive(projectID)
	assert.Len(t, allActive, 0)
}

// TestRetryLogic тестирует retry логику
func TestRetryLogic(t *testing.T) {
	attempts := 0
	maxAttempts := 3

	err := WithRetry(context.Background(), func() error {
		attempts++
		if attempts < maxAttempts {
			return status.Error(codes.Unavailable, "temporary error")
		}
		return nil
	}, &RetryConfig{
		MaxAttempts:    maxAttempts,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})

	assert.NoError(t, err)
	assert.Equal(t, maxAttempts, attempts)
}

// TestRetryLogicNonRetryable тестирует retry логику с non-retryable ошибкой
func TestRetryLogicNonRetryable(t *testing.T) {
	attempts := 0

	err := WithRetry(context.Background(), func() error {
		attempts++
		return status.Error(codes.InvalidArgument, "invalid argument")
	}, &RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})

	assert.Error(t, err)
	assert.Equal(t, 1, attempts) // Должна быть только одна попытка
}

// TestClientIssueToken тестирует IssueToken
func TestClientIssueToken(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       DefaultConfig("localhost:50051"),
	}

	req := &authv1.IssueTokenRequest{
		UserId: "user-123",
	}

	expectedResp := &authv1.IssueTokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		KeyId:        "key-1",
	}

	mockJWT.On("IssueToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.IssueToken(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp.AccessToken, resp.AccessToken)
	mockJWT.AssertExpectations(t)
}

// TestClientGetPublicKeyWithCache тестирует GetPublicKey с кэшированием
func TestClientGetPublicKeyWithCache(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	cache := NewKeyCache(nil)
	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     cache,
		config:       DefaultConfig("localhost:50051"),
	}

	projectID := "test-project"
	keyID := "key-1"
	keyInfo := &authv1.PublicKeyInfo{
		KeyId:        keyID,
		PublicKeyPem: "cached-key",
		Algorithm:    "RS256",
	}

	// Сохраняем в кэш
	cache.Set(projectID, keyInfo, time.Now().Add(1*time.Hour).Unix())

	// Запрос должен вернуть из кэша, без вызова сервера
	req := &authv1.GetPublicKeyRequest{
		ProjectId: projectID,
		KeyId:     keyID,
	}

	resp, err := cl.GetPublicKey(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, keyInfo.PublicKeyPem, resp.PublicKeyPem)
	mockJWT.AssertNotCalled(t, "GetPublicKey")
}

// TestDefaultConfig тестирует создание конфигурации по умолчанию
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig("localhost:50051")
	assert.Equal(t, "localhost:50051", config.Address)
	assert.NotNil(t, config.TLS)
	assert.NotNil(t, config.Retry)
	assert.NotNil(t, config.KeyCache)
	assert.NotNil(t, config.Timeout)
	assert.Equal(t, 3, config.Retry.MaxAttempts)
}

// TestIssueServiceTokenWithServiceAuth тестирует IssueServiceToken с service authentication
func TestIssueServiceTokenWithServiceAuth(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	config.ServiceName = "identity-service"
	config.ServiceSecret = "identity-service-secret-abc123"

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
		TargetService: "gateway-service",
		UserId:        "user-123",
	}

	expectedResp := &authv1.IssueTokenResponse{
		AccessToken:  "service-token",
		RefreshToken: "",
		KeyId:        "key-1",
	}

	mockJWT.On("IssueServiceToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.IssueServiceToken(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp.AccessToken, resp.AccessToken)
	mockJWT.AssertExpectations(t)
}

// TestIssueServiceTokenWithoutServiceAuth тестирует IssueServiceToken без service authentication (v1.0+)
// Service auth теперь опциональна
func TestIssueServiceTokenWithoutServiceAuth(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	// ServiceName и ServiceSecret не установлены - это допустимо (v1.0+)

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
	}

	expectedResp := &authv1.IssueTokenResponse{
		AccessToken:  "service-token",
		RefreshToken: "",
		KeyId:        "key-1",
	}

	mockJWT.On("IssueServiceToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.IssueServiceToken(context.Background(), req)
	assert.NoError(t, err) // Не должно быть ошибки - service auth опциональна (v1.0+)
	assert.Equal(t, expectedResp.AccessToken, resp.AccessToken)
	mockJWT.AssertExpectations(t)
}

// TestValidateTokenWithJWT тестирует ValidateToken с JWT token в конфигурации
// В v1.0+ JWT токен не должен добавляться для ValidateToken (опциональная аутентификация)
// Но тест оставляем для обратной совместимости конфигурации
func TestValidateTokenWithJWT(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	// JWT токен в конфиге не должен влиять на ValidateToken в v1.0+
	// config.JWTToken не устанавливаем - ValidateToken использует опциональную service auth или public

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.ValidateTokenRequest{
		Token:          "token-to-validate",
		CheckBlacklist: true,
	}

	expectedResp := &authv1.ValidateTokenResponse{
		Valid: true,
		Claims: &authv1.TokenClaims{
			UserId: "user-123",
		},
	}

	mockJWT.On("ValidateToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.ValidateToken(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Valid)
	mockJWT.AssertExpectations(t)
}

// TestValidateTokenWithoutAuth тестирует ValidateToken без аутентификации (v1.0+)
func TestValidateTokenWithoutAuth(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	// Ни JWT токен, ни service auth не установлены - это допустимо (v1.0+)

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.ValidateTokenRequest{
		Token:          "token-to-validate",
		CheckBlacklist: true,
	}

	expectedResp := &authv1.ValidateTokenResponse{
		Valid: true,
		Claims: &authv1.TokenClaims{
			UserId: "user-123",
		},
	}

	mockJWT.On("ValidateToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.ValidateToken(context.Background(), req)
	assert.NoError(t, err) // Не должно быть ошибки - аутентификация опциональна (v1.0+)
	assert.True(t, resp.Valid)
	mockJWT.AssertExpectations(t)
}

// TestWrapErrorPermissionDenied тестирует обработку PermissionDenied ошибки
func TestWrapErrorPermissionDenied(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		expectedErr      error
		checkServiceAuth bool
	}{
		{
			name:             "Service authentication failed",
			err:              status.Error(codes.PermissionDenied, "service authentication failed: invalid service-name or service-secret"),
			expectedErr:      ErrServiceAuthFailed,
			checkServiceAuth: true,
		},
		{
			name:             "General PermissionDenied",
			err:              status.Error(codes.PermissionDenied, "permission denied"),
			expectedErr:      nil, // Should return ClientError with ERROR_UNKNOWN
			checkServiceAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapError(tt.err)
			assert.Error(t, wrapped)

			if tt.checkServiceAuth {
				assert.True(t, errors.Is(wrapped, ErrServiceAuthFailed))
			} else {
				var clientErr *ClientError
				assert.True(t, errors.As(wrapped, &clientErr))
				assert.Equal(t, authv1.ErrorCode_ERROR_UNKNOWN, clientErr.Code)
			}
		})
	}
}

// TestWrapErrorUnauthenticated тестирует обработку Unauthenticated ошибки
func TestWrapErrorUnauthenticated(t *testing.T) {
	err := status.Error(codes.Unauthenticated, "JWT authentication failed")
	wrapped := WrapError(err)

	var clientErr *ClientError
	assert.True(t, errors.As(wrapped, &clientErr))
	assert.Equal(t, authv1.ErrorCode_ERROR_UNKNOWN, clientErr.Code)
}

// TestMetadataProjectID тестирует добавление project-id в metadata (v1.0+)
func TestMetadataProjectID(t *testing.T) {
	config := DefaultConfig("localhost:50051")
	config.ProjectID = "default-project-id"

	cl := &Client{
		config: config,
	}

	ctx := context.Background()
	ctx = cl.withMetadata(ctx, "", false)

	md, ok := metadata.FromOutgoingContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, []string{"default-project-id"}, md.Get("project-id"))
}

// TestMetadataJWTOnlyForRequiredMethods тестирует, что JWT токен добавляется только для методов, требующих JWT (v1.0+)
func TestMetadataJWTOnlyForRequiredMethods(t *testing.T) {
	config := DefaultConfig("localhost:50051")
	config.JWTToken = "test-jwt-token"

	cl := &Client{
		config: config,
	}

	ctx := context.Background()

	// Для методов без требования JWT - JWT не должен добавляться
	ctx1 := cl.withMetadata(ctx, "", false)
	md1, _ := metadata.FromOutgoingContext(ctx1)
	assert.Empty(t, md1.Get("authorization"))

	// Для методов с требованием JWT - JWT должен добавляться
	ctx2 := cl.withMetadata(ctx, "", true)
	md2, _ := metadata.FromOutgoingContext(ctx2)
	assert.Equal(t, []string{"Bearer test-jwt-token"}, md2.Get("authorization"))
}

// TestRevokeTokenRequiresJWT тестирует, что RevokeToken требует JWT токен (v1.0+)
func TestRevokeTokenRequiresJWT(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	config.JWTToken = "test-jwt-token"

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.RevokeTokenRequest{
		Token: "token-to-revoke",
	}

	expectedResp := &authv1.RevokeTokenResponse{
		Success: true,
	}

	mockJWT.On("RevokeToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.RevokeToken(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	mockJWT.AssertExpectations(t)
}

// TestAPIKeyMethodsRequireJWT тестирует, что методы APIKeyService требуют JWT токен (v1.0+)
func TestAPIKeyMethodsRequireJWT(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	config.JWTToken = "test-jwt-token"

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	// Test CreateAPIKey
	createReq := &authv1.CreateAPIKeyRequest{
		ProjectId: "project-123",
		Name:      "test-key",
	}
	createResp := &authv1.CreateAPIKeyResponse{
		ApiKey: "test-api-key",
		KeyId:  "key-1",
	}
	mockAPIKey.On("CreateAPIKey", mock.Anything, createReq).Return(createResp, nil)

	resp, err := cl.CreateAPIKey(context.Background(), createReq)
	assert.NoError(t, err)
	assert.Equal(t, "test-api-key", resp.ApiKey)
	mockAPIKey.AssertExpectations(t)
}

// TestValidateTokenWithoutJWT тестирует, что ValidateToken не требует JWT токен (v1.0+)
func TestValidateTokenWithoutJWT(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	// JWT токен не установлен - ValidateToken должен работать

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.ValidateTokenRequest{
		Token:          "token-to-validate",
		CheckBlacklist: true,
	}

	expectedResp := &authv1.ValidateTokenResponse{
		Valid: true,
		Claims: &authv1.TokenClaims{
			UserId: "user-123",
		},
	}

	mockJWT.On("ValidateToken", mock.Anything, req).Return(expectedResp, nil)

	resp, err := cl.ValidateToken(context.Background(), req)
	assert.NoError(t, err) // Не должно быть ошибки даже без JWT токена
	assert.True(t, resp.Valid)
	mockJWT.AssertExpectations(t)
}

// TestMetadataServiceAuth тестирует добавление service authentication в metadata
func TestMetadataServiceAuth(t *testing.T) {
	config := DefaultConfig("localhost:50051")
	config.ServiceName = "test-service"
	config.ServiceSecret = "test-secret"

	cl := &Client{
		config: config,
	}

	ctx := context.Background()
	ctx = cl.withMetadata(ctx, "", false)

	md, ok := metadata.FromOutgoingContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, []string{"test-service"}, md.Get("service-name"))
	assert.Equal(t, []string{"test-secret"}, md.Get("service-secret"))
}
