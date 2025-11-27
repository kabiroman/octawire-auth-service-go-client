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
	"google.golang.org/grpc/status"

	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
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
		name     string
		err      error
		checkFn  func(error) bool
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

// TestIssueServiceTokenWithoutServiceAuth тестирует IssueServiceToken без service authentication
func TestIssueServiceTokenWithoutServiceAuth(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	// ServiceName и ServiceSecret не установлены

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.IssueServiceTokenRequest{
		SourceService: "identity-service",
	}

	_, err := cl.IssueServiceToken(context.Background(), req)
	assert.Error(t, err)
	var clientErr *ClientError
	assert.True(t, errors.As(err, &clientErr))
	assert.Contains(t, clientErr.Message, "service authentication required")
	mockJWT.AssertNotCalled(t, "IssueServiceToken")
}

// TestValidateTokenWithJWT тестирует ValidateToken с JWT token в конфигурации
func TestValidateTokenWithJWT(t *testing.T) {
	mockJWT := new(MockJWTServiceClient)
	mockAPIKey := new(MockAPIKeyServiceClient)

	config := DefaultConfig("localhost:50051")
	config.JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

	cl := &Client{
		jwtClient:    mockJWT,
		apiKeyClient: mockAPIKey,
		keyCache:     NewKeyCache(nil),
		config:       config,
	}

	req := &authv1.ValidateTokenRequest{
		Token:         "token-to-validate",
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

// TestWrapErrorPermissionDenied тестирует обработку PermissionDenied ошибки
func TestWrapErrorPermissionDenied(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedErr    error
		checkServiceAuth bool
	}{
		{
			name: "Service authentication failed",
			err:  status.Error(codes.PermissionDenied, "service authentication failed: invalid service-name or service-secret"),
			expectedErr: ErrServiceAuthFailed,
			checkServiceAuth: true,
		},
		{
			name: "General PermissionDenied",
			err:  status.Error(codes.PermissionDenied, "permission denied"),
			expectedErr: nil, // Should return ClientError with ERROR_UNKNOWN
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

