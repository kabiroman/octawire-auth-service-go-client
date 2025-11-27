# Go Client для Auth Service

Go клиент для работы с Auth Service (v0.9.3) через gRPC.

**Репозиторий:** [https://github.com/kabiroman/octawire-auth-service-go-client](https://github.com/kabiroman/octawire-auth-service-go-client)

## Установка

```bash
go get github.com/kabiroman/octawire-auth-service-go-client
```

## Быстрый старт

```go
package main

import (
    "context"
    "log"
    
    "github.com/kabiroman/octawire-auth-service-go-client"
    authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
)

func main() {
    // Создаем клиент
    config := client.DefaultConfig("localhost:50051")
    config.ProjectID = "your-project-id"
    
    cl, err := client.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer cl.Close()
    
    // Выдаем токен
    resp, err := cl.IssueToken(context.Background(), &authv1.IssueTokenRequest{
        UserId: "user-123",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Access Token: %s", resp.AccessToken)
}
```

## Конфигурация

### Базовая конфигурация

```go
config := client.DefaultConfig("localhost:50051")
config.ProjectID = "default-project-id"
config.APIKey = "your-api-key" // Опционально
```

### Service Authentication

Для использования `IssueServiceToken` требуется service authentication:

```go
config.ServiceName = "identity-service"
config.ServiceSecret = "identity-service-secret-abc123"
```

### JWT Authentication

Для методов, требующих JWT аутентификации (ValidateToken, ParseToken, RevokeToken, ValidateBatch, ExtractClaims, и все методы APIKeyService), требуется JWT токен:

```go
config.JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### TLS/mTLS конфигурация

```go
config.TLS = &client.TLSConfig{
    Enabled:    true,
    CAFile:     "/path/to/ca.crt",
    CertFile:   "/path/to/client.crt", // Для mTLS
    KeyFile:    "/path/to/client.key", // Для mTLS
    ServerName: "auth-service.example.com",
}
```

### Retry конфигурация

```go
config.Retry = &client.RetryConfig{
    MaxAttempts:    3,
    InitialBackoff: 100 * time.Millisecond,
    MaxBackoff:     5 * time.Second,
}
```

### Кэш ключей

```go
config.KeyCache = &client.KeyCacheConfig{
    TTL:     1 * time.Hour,
    MaxSize: 100, // Максимальное количество проектов в кэше
}
```

### Таймауты

```go
config.Timeout = &client.TimeoutConfig{
    Connect: 10 * time.Second,
    Request: 30 * time.Second,
}
```

## Project ID (v0.9.3+)

`project_id` is now required in payload for all token-related methods. The client automatically sets `default-project-id` in gRPC metadata from `config.ProjectID` if `project_id` is not provided in the request.

**Priority:**
1. `project_id` in request payload (highest priority)
2. `default-project-id` in gRPC metadata (from `config.ProjectID`)
3. Legacy mode (if service has no projects configured)

### Example with project_id in payload:

```go
resp, err := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId: "user-123",
    ProjectId: "project-id", // Required (v0.9.3+)
})
```

### Example with default-project-id in metadata:

```go
config.ProjectID = "default-project-id" // Set in metadata as default-project-id
cl, _ := client.NewClient(config)

resp, err := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId: "user-123",
    ProjectId: "", // Empty - will use default-project-id from metadata
})
```

## Использование

### JWT Service методы

#### IssueToken - Выдача токена

```go
resp, err := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId: "user-123",
    Claims: map[string]string{
        "role": "admin",
    },
    AccessTokenTtl:  3600,
    RefreshTokenTtl: 86400,
    ProjectId:       "project-id", // Required (v0.9.3+)
})
```

#### ValidateToken - Валидация токена

**Требует JWT аутентификации** (JWTToken должен быть установлен в конфигурации):

```go
// Настройка JWT токена
config.JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
cl, _ := client.NewClient(config)

// Валидация токена
resp, err := cl.ValidateToken(ctx, &authv1.ValidateTokenRequest{
    Token:         "jwt-token",
    ProjectId:     "project-id", // Required (v0.9.3+)
    CheckBlacklist: true,
})

if resp.Valid {
    // Токен валиден
    claims := resp.Claims
    // ...
}
```

#### RefreshToken - Обновление токена

```go
resp, err := cl.RefreshToken(ctx, &authv1.RefreshTokenRequest{
    RefreshToken: "refresh-token",
    ProjectId:    "project-id", // Required (v0.9.3+)
})
```

#### GetPublicKey - Получение публичного ключа (с кэшированием)

```go
resp, err := cl.GetPublicKey(ctx, &authv1.GetPublicKeyRequest{
    ProjectId: "project-id",
    KeyId:     "key-id", // Опционально
})
```

Метод автоматически кэширует ключи и использует кэш при повторных запросах.

#### IssueServiceToken - Выдача межсервисного токена

**Требует service authentication** (ServiceName и ServiceSecret должны быть установлены в конфигурации):

```go
// Настройка service authentication
config.ServiceName = "identity-service"
config.ServiceSecret = "identity-service-secret-abc123"
cl, _ := client.NewClient(config)

// Выдача межсервисного токена
resp, err := cl.IssueServiceToken(ctx, &authv1.IssueServiceTokenRequest{
    SourceService: "identity-service",
    TargetService: "gateway-service",
    UserId:        "user-123",
    Claims: map[string]string{
        "role": "admin",
    },
    Ttl:       3600,
    ProjectId: "project-id",
})
```

#### Другие методы

- `RevokeToken` - отзыв токена (требует JWT аутентификации)
- `ParseToken` - парсинг токена без валидации (требует JWT аутентификации)
- `ExtractClaims` - извлечение claims из токена (требует JWT аутентификации)
- `ValidateBatch` - пакетная валидация токенов (требует JWT аутентификации)
- `HealthCheck` - проверка здоровья сервиса (публичный метод)

### API Key Service методы

**Все методы APIKeyService требуют JWT аутентификации** (JWTToken должен быть установлен в конфигурации).

#### CreateAPIKey - Создание API ключа

```go
// Настройка JWT токена
config.JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
cl, _ := client.NewClient(config)

resp, err := cl.CreateAPIKey(ctx, &authv1.CreateAPIKeyRequest{
    ProjectId: "project-id",
    UserId:    "user-id", // Опционально
    Name:      "My API Key",
    Scopes:    []string{"read", "write"},
    Ttl:       86400 * 30, // 30 дней
})
```

#### ValidateAPIKey - Валидация API ключа

```go
resp, err := cl.ValidateAPIKey(ctx, &authv1.ValidateAPIKeyRequest{
    ApiKey:        "api-key",
    RequiredScopes: []string{"read"},
})
```

#### ListAPIKeys - Список API ключей

```go
resp, err := cl.ListAPIKeys(ctx, &authv1.ListAPIKeysRequest{
    ProjectId: "project-id",
    UserId:    "user-id", // Опционально
    Page:      1,
    PageSize:  10,
})
```

#### RevokeAPIKey - Отзыв API ключа

```go
resp, err := cl.RevokeAPIKey(ctx, &authv1.RevokeAPIKeyRequest{
    KeyId:     "key-id",
    ProjectId: "project-id",
})
```

## Кэширование публичных ключей

Клиент автоматически кэширует публичные ключи для оптимизации производительности. Кэш поддерживает graceful key rotation - хранение нескольких активных ключей одновременно.

### Управление кэшем

```go
// Получить кэш
keyCache := cl.GetKeyCache()

// Получить все активные ключи для проекта
activeKeys := keyCache.GetAllActive("project-id")

// Инвалидировать кэш для проекта
keyCache.Invalidate("project-id")

// Очистить весь кэш
keyCache.Clear()

// Очистить истекшие ключи
keyCache.CleanupExpired()
```

### Graceful Key Rotation

При ротации ключей сервер возвращает список всех активных ключей в поле `active_keys`. Клиент автоматически кэширует все активные ключи, что позволяет валидировать токены, подписанные как старыми, так и новыми ключами во время ротации.

```go
resp, err := cl.GetPublicKey(ctx, &authv1.GetPublicKeyRequest{
    ProjectId: "project-id",
})

// resp.ActiveKeys содержит все активные ключи
for _, key := range resp.ActiveKeys {
    fmt.Printf("Key ID: %s, Primary: %v, Expires At: %s\n",
        key.KeyId, key.IsPrimary, time.Unix(key.ExpiresAt, 0))
}
```

Клиент использует `cache_until` из ответа для определения времени жизни кэша. Если `cache_until` не указан, используется `TTL` из конфигурации или время истечения самого ключа.

## Retry логика

Клиент автоматически повторяет запросы при временных ошибках (Unavailable, DeadlineExceeded, ResourceExhausted) с экспоненциальным backoff и jitter.

Настройки retry:

```go
config.Retry = &client.RetryConfig{
    MaxAttempts:    3,                      // Максимум попыток
    InitialBackoff: 100 * time.Millisecond, // Начальная задержка
    MaxBackoff:     5 * time.Second,        // Максимальная задержка
}
```

## Обработка ошибок

Клиент оборачивает gRPC ошибки в понятные типы:

```go
resp, err := cl.ValidateToken(ctx, req)
if err != nil {
    if errors.Is(err, client.ErrInvalidToken) {
        // Токен невалиден
    } else if errors.Is(err, client.ErrTokenExpired) {
        // Токен истек
    } else if errors.Is(err, client.ErrTokenRevoked) {
        // Токен отозван
    } else if errors.Is(err, client.ErrServiceAuthFailed) {
        // Ошибка service authentication (неверный service-name или service-secret)
    } else if errors.Is(err, client.ErrConnectionFailed) {
        // Ошибка подключения
    } else if errors.Is(err, client.ErrRateLimitExceeded) {
        // Превышен лимит запросов
    }
}
```

### Типы ошибок

- `ErrInvalidToken` - Токен невалиден (синтаксис, формат, подпись)
- `ErrTokenExpired` - Токен истек
- `ErrTokenRevoked` - Токен отозван (в blacklist)
- `ErrServiceAuthFailed` - Ошибка service authentication (неверный service-name или service-secret)
- `ErrConnectionFailed` - Ошибка подключения к серверу
- `ErrRateLimitExceeded` - Превышен лимит запросов

## Работа с несколькими проектами

Клиент поддерживает работу с несколькими проектами. Вы можете указать `ProjectID` в конфигурации (для всех запросов) или в каждом запросе отдельно:

```go
// Дефолтный проект из конфигурации
config.ProjectID = "default-project-id"
cl, _ := client.NewClient(config)

// Использование дефолтного проекта
resp, _ := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId: "user-123",
    // ProjectId не указан, используется из конфигурации
})

// Использование другого проекта
resp, _ := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId:    "user-123",
    ProjectId: "another-project-id",
})
```

## Примеры

Полные примеры использования находятся в директории `examples/`:

- `examples/basic/main.go` - базовое использование
- `examples/tls/main.go` - использование с TLS/mTLS
- `examples/caching/main.go` - демонстрация кэширования ключей
- `examples/multiproject/main.go` - работа с несколькими проектами
- `examples/test-scenarios/main.go` - тестирование всех сценариев конфигурации

## Тестирование

### Юнит-тесты

```bash
go test ./...
```

### Интеграционные тесты

Интеграционные тесты проверяют работу клиента со всеми комбинациями конфигураций:
- DEV/PROD окружения
- service_auth включен/выключен

Требуется запущенный экземпляр auth-service:

```bash
# Запустить интеграционные тесты
go test -v -integration=true [-service-address=localhost:50051] [-api-key=your-api-key]

# Или использовать пример test-scenarios
cd examples/test-scenarios
go run main.go -scenario dev-sa-true
```

Доступные сценарии:
- `dev-sa-false` - DEV с service_auth отключен
- `dev-sa-true` - DEV с service_auth включен
- `prod-sa-false` - PROD с service_auth отключен
- `prod-sa-true` - PROD с service_auth включен

Интеграционные тесты автоматически определяют требования TLS и адаптируются к конфигурации сервера.

## Репозиторий

- **GitHub:** [https://github.com/kabiroman/octawire-auth-service-go-client](https://github.com/kabiroman/octawire-auth-service-go-client)

## Лицензия

См. основной репозиторий проекта.

