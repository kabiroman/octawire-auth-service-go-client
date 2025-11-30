package client

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
)

// Version is the current version of the client library
const Version = "0.9.4"

// Client представляет клиент для Auth Service
type Client struct {
	conn         *grpc.ClientConn
	jwtClient    authv1.JWTServiceClient
	apiKeyClient authv1.APIKeyServiceClient
	keyCache     *KeyCache
	config       *ClientConfig
}

// NewClient создает новый клиент и устанавливает соединение с сервером
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, &ClientError{Message: "config is required"}
	}

	if config.Address == "" {
		return nil, &ClientError{Message: "address is required"}
	}

	// Загружаем TLS конфигурацию
	tlsOption, err := LoadTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}

	// Настраиваем опции подключения
	opts := []grpc.DialOption{
		tlsOption,
	}

	// Устанавливаем таймаут подключения
	if config.Timeout != nil && config.Timeout.Connect > 0 {
		opts = append(opts, grpc.WithTimeout(config.Timeout.Connect))
	}

	// Устанавливаем соединение
	conn, err := grpc.NewClient(config.Address, opts...)
	if err != nil {
		// Улучшаем сообщение об ошибке подключения
		wrappedErr := WrapError(err)
		errStr := err.Error()

		// Добавляем полезную информацию о конфигурации TLS
		if config.TLS != nil && !config.TLS.Enabled {
			if strings.Contains(strings.ToLower(errStr), "tls") || strings.Contains(strings.ToLower(errStr), "certificate") {
				return nil, fmt.Errorf("%w: server may require TLS connection (check TLS configuration)", wrappedErr)
			}
		}

		return nil, wrappedErr
	}

	// Создаем клиенты
	jwtClient := authv1.NewJWTServiceClient(conn)
	apiKeyClient := authv1.NewAPIKeyServiceClient(conn)

	// Создаем кэш ключей
	keyCache := NewKeyCache(config.KeyCache)

	return &Client{
		conn:         conn,
		jwtClient:    jwtClient,
		apiKeyClient: apiKeyClient,
		keyCache:     keyCache,
		config:       config,
	}, nil
}

// Close закрывает соединение с сервером
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// withContext создает контекст с таймаутом и метаданными
func (c *Client) withContext(ctx context.Context, projectID string, requireJWT bool) (context.Context, context.CancelFunc) {
	// Устанавливаем таймаут запроса
	if c.config.Timeout != nil && c.config.Timeout.Request > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.Timeout.Request)
		return c.withMetadata(ctx, projectID, requireJWT), cancel
	}

	// Создаем cancel функцию для контекста без таймаута
	ctx, cancel := context.WithCancel(ctx)
	return c.withMetadata(ctx, projectID, requireJWT), cancel
}

// withMetadata добавляет метаданные к контексту
// requireJWT указывает, требуется ли JWT токен для этого метода (только для RevokeToken и APIKeyService методов)
func (c *Client) withMetadata(ctx context.Context, projectID string, requireJWT bool) context.Context {
	md := metadata.New(nil)

	// Добавляем project-id в metadata (v1.0+)
	if projectID != "" {
		md.Set("project-id", projectID)
	} else if c.config.ProjectID != "" {
		md.Set("project-id", c.config.ProjectID)
	}

	// Добавляем API ключ, если указан
	if c.config.APIKey != "" {
		md.Set("api-key", c.config.APIKey)
	}

	// Добавляем service authentication, если указано
	if c.config.ServiceName != "" && c.config.ServiceSecret != "" {
		md.Set("service-name", c.config.ServiceName)
		md.Set("service-secret", c.config.ServiceSecret)
	}

	// Добавляем JWT token только для методов, требующих JWT аутентификации (v1.0+)
	if requireJWT && c.config.JWTToken != "" {
		md.Set("authorization", "Bearer "+c.config.JWTToken)
	}

	return metadata.NewOutgoingContext(ctx, md)
}

// getProjectID возвращает project_id из параметра или конфигурации
func (c *Client) getProjectID(projectID string) string {
	if projectID != "" {
		return projectID
	}
	return c.config.ProjectID
}

// JWTService методы

// IssueToken выдает новый JWT токен (access + refresh)
func (c *Client) IssueToken(ctx context.Context, req *authv1.IssueTokenRequest) (*authv1.IssueTokenResponse, error) {
	// Set ProjectId from config if not provided in request (v0.9.3+)
	projectID := c.getProjectID(req.ProjectId)
	if req.ProjectId == "" && projectID != "" {
		req.ProjectId = projectID
	}
	ctx, cancel := c.withContext(ctx, projectID, false)
	defer cancel()

	var resp *authv1.IssueTokenResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.IssueToken(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// IssueServiceToken выдает межсервисный JWT токен
// Service authentication опциональна (v1.0+): если service_auth.enabled = true на сервере,
// service authentication доступна но не обязательна (рекомендуется для production)
func (c *Client) IssueServiceToken(ctx context.Context, req *authv1.IssueServiceTokenRequest) (*authv1.IssueTokenResponse, error) {
	projectID := c.getProjectID(req.ProjectId)
	ctx, cancel := c.withContext(ctx, projectID, false)
	defer cancel()

	var resp *authv1.IssueTokenResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.IssueServiceToken(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// ValidateToken валидирует токен
// Authentication опциональна (v1.0+): service auth опциональна (если service_auth.enabled = true),
// или можно использовать JWT token, или public для localhost соединений
func (c *Client) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	// project-id передается через metadata, не через payload
	ctx, cancel := c.withContext(ctx, c.config.ProjectID, false)
	defer cancel()

	var resp *authv1.ValidateTokenResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.ValidateToken(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// RefreshToken обновляет токен
func (c *Client) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	// project-id передается через metadata, не через payload
	ctx, cancel := c.withContext(ctx, c.config.ProjectID, false)
	defer cancel()

	var resp *authv1.RefreshTokenResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.RefreshToken(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// RevokeToken отзывает токен
// Требует JWT аутентификации: JWTToken должен быть установлен в конфигурации
func (c *Client) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest) (*authv1.RevokeTokenResponse, error) {
	// project-id передается через metadata, не через payload
	ctx, cancel := c.withContext(ctx, c.config.ProjectID, true) // JWT required
	defer cancel()

	var resp *authv1.RevokeTokenResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.RevokeToken(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// ParseToken парсит токен без валидации
// Authentication опциональна (v1.0+): service auth опциональна (если service_auth.enabled = true),
// или public (без аутентификации, особенно для localhost соединений)
func (c *Client) ParseToken(ctx context.Context, req *authv1.ParseTokenRequest) (*authv1.ParseTokenResponse, error) {
	// project-id передается через metadata, не через payload
	ctx, cancel := c.withContext(ctx, c.config.ProjectID, false)
	defer cancel()

	var resp *authv1.ParseTokenResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.ParseToken(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// ExtractClaims извлекает claims из токена
// Authentication опциональна (v1.0+): service auth опциональна (если service_auth.enabled = true),
// или public (без аутентификации, особенно для localhost соединений)
func (c *Client) ExtractClaims(ctx context.Context, req *authv1.ExtractClaimsRequest) (*authv1.ExtractClaimsResponse, error) {
	// project-id передается через metadata, не через payload
	ctx, cancel := c.withContext(ctx, c.config.ProjectID, false)
	defer cancel()

	var resp *authv1.ExtractClaimsResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.ExtractClaims(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// ValidateBatch выполняет пакетную валидацию токенов
// Authentication опциональна (v1.0+): service auth опциональна (если service_auth.enabled = true),
// или можно использовать JWT token, или public для localhost соединений
func (c *Client) ValidateBatch(ctx context.Context, req *authv1.ValidateBatchRequest) (*authv1.ValidateBatchResponse, error) {
	ctx, cancel := c.withContext(ctx, "", false)
	defer cancel()

	var resp *authv1.ValidateBatchResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.ValidateBatch(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// GetPublicKey получает публичный ключ для проекта (с кэшированием)
func (c *Client) GetPublicKey(ctx context.Context, req *authv1.GetPublicKeyRequest) (*authv1.GetPublicKeyResponse, error) {
	projectID := c.getProjectID(req.ProjectId)

	// Если указан key_id, пытаемся получить из кэша
	if req.KeyId != "" {
		if keyInfo, ok := c.keyCache.Get(projectID, req.KeyId); ok {
			// Возвращаем ответ из кэша
			return &authv1.GetPublicKeyResponse{
				PublicKeyPem: keyInfo.PublicKeyPem,
				Algorithm:    keyInfo.Algorithm,
				KeyId:        keyInfo.KeyId,
				ProjectId:    projectID,
			}, nil
		}
	}

	// Если не найден в кэше или не указан key_id, запрашиваем у сервера
	ctx, cancel := c.withContext(ctx, projectID, false)
	defer cancel()

	var resp *authv1.GetPublicKeyResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.GetPublicKey(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	// Сохраняем в кэш
	if resp != nil {
		// Сохраняем основной ключ
		if resp.KeyId != "" {
			keyInfo := &authv1.PublicKeyInfo{
				KeyId:        resp.KeyId,
				PublicKeyPem: resp.PublicKeyPem,
				Algorithm:    resp.Algorithm,
			}
			c.keyCache.Set(projectID, keyInfo, resp.CacheUntil)
		}

		// Сохраняем все активные ключи для graceful ротации
		if len(resp.ActiveKeys) > 0 {
			c.keyCache.SetAllActive(projectID, resp.ActiveKeys, resp.CacheUntil)
		}
	}

	return resp, nil
}

// HealthCheck проверяет здоровье сервиса
func (c *Client) HealthCheck(ctx context.Context) (*authv1.HealthCheckResponse, error) {
	ctx, cancel := c.withContext(ctx, "", false)
	defer cancel()

	req := &authv1.HealthCheckRequest{}
	var resp *authv1.HealthCheckResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.jwtClient.HealthCheck(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// APIKeyService методы

// CreateAPIKey создает новый API ключ
// Требует JWT аутентификации: JWTToken должен быть установлен в конфигурации
func (c *Client) CreateAPIKey(ctx context.Context, req *authv1.CreateAPIKeyRequest) (*authv1.CreateAPIKeyResponse, error) {
	projectID := c.getProjectID(req.ProjectId)
	ctx, cancel := c.withContext(ctx, projectID, true) // JWT required
	defer cancel()

	var resp *authv1.CreateAPIKeyResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.apiKeyClient.CreateAPIKey(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// ValidateAPIKey валидирует API ключ
// Требует JWT аутентификации: JWTToken должен быть установлен в конфигурации
func (c *Client) ValidateAPIKey(ctx context.Context, req *authv1.ValidateAPIKeyRequest) (*authv1.ValidateAPIKeyResponse, error) {
	ctx, cancel := c.withContext(ctx, "", true) // JWT required
	defer cancel()

	var resp *authv1.ValidateAPIKeyResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.apiKeyClient.ValidateAPIKey(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// RevokeAPIKey отзывает API ключ
// Требует JWT аутентификации: JWTToken должен быть установлен в конфигурации
func (c *Client) RevokeAPIKey(ctx context.Context, req *authv1.RevokeAPIKeyRequest) (*authv1.RevokeAPIKeyResponse, error) {
	projectID := c.getProjectID(req.ProjectId)
	ctx, cancel := c.withContext(ctx, projectID, true) // JWT required
	defer cancel()

	var resp *authv1.RevokeAPIKeyResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.apiKeyClient.RevokeAPIKey(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// ListAPIKeys возвращает список API ключей
// Требует JWT аутентификации: JWTToken должен быть установлен в конфигурации
func (c *Client) ListAPIKeys(ctx context.Context, req *authv1.ListAPIKeysRequest) (*authv1.ListAPIKeysResponse, error) {
	projectID := c.getProjectID(req.ProjectId)
	ctx, cancel := c.withContext(ctx, projectID, true) // JWT required
	defer cancel()

	var resp *authv1.ListAPIKeysResponse
	err := WithRetry(ctx, func() error {
		var err error
		resp, err = c.apiKeyClient.ListAPIKeys(ctx, req)
		return err
	}, c.config.Retry)

	if err != nil {
		return nil, WrapError(err)
	}

	return resp, nil
}

// GetKeyCache возвращает кэш ключей (для управления)
func (c *Client) GetKeyCache() *KeyCache {
	return c.keyCache
}
