# Go Client для Auth Service

Go клиент для работы с Auth Service (v0.9.1) через gRPC.

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
    authv1 "github.com/octawire/auth-service/internal/proto"
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
    ProjectId:       "project-id", // Опционально
})
```

#### ValidateToken - Валидация токена

```go
resp, err := cl.ValidateToken(ctx, &authv1.ValidateTokenRequest{
    Token:         "jwt-token",
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

#### Другие методы

- `IssueServiceToken` - выдача межсервисного токена
- `RevokeToken` - отзыв токена
- `ParseToken` - парсинг токена без валидации
- `ExtractClaims` - извлечение claims из токена
- `ValidateBatch` - пакетная валидация токенов
- `HealthCheck` - проверка здоровья сервиса

### API Key Service методы

#### CreateAPIKey - Создание API ключа

```go
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
    } else if errors.Is(err, client.ErrConnectionFailed) {
        // Ошибка подключения
    } else if errors.Is(err, client.ErrRateLimitExceeded) {
        // Превышен лимит запросов
    }
}
```

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

## Тестирование

```bash
go test ./...
```

## Репозиторий

- **GitHub:** [https://github.com/kabiroman/octawire-auth-service-go-client](https://github.com/kabiroman/octawire-auth-service-go-client)

## Лицензия

См. основной репозиторий проекта.

