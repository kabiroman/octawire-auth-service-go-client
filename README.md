# Go Client для Auth Service

Go клиент для работы с Auth Service (v1.0) через gRPC.

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
        UserId:    "user-123",
        ProjectId: "your-project-id", // Required (v1.0+)
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

## Authentication Types (v1.0+)

### Public Methods
Следующие методы не требуют аутентификации:
- `IssueToken`
- `RefreshToken`
- `GetPublicKey`
- `HealthCheck`

### Optional Service Authentication (v1.0+)
Следующие методы поддерживают опциональную service authentication:
- `IssueServiceToken` - service auth опциональна (рекомендуется для production)
- `ValidateToken` - service auth опциональна, или public (без аутентификации, особенно для localhost)
- `ParseToken` - service auth опциональна, или public (без аутентификации, особенно для localhost)
- `ExtractClaims` - service auth опциональна, или public (без аутентификации, особенно для localhost)
- `ValidateBatch` - service auth опциональна, или public (без аутентификации, особенно для localhost)

### JWT Authentication Required
Следующие методы требуют JWT токен:
- `RevokeToken` - требует JWT (user revoking their own token)
- Все методы `APIKeyService.*` - требуют JWT (key management operations)

### Service Authentication

Для методов с опциональной service authentication (IssueServiceToken, ValidateToken, ParseToken, ExtractClaims, ValidateBatch):

```go
config.ServiceName = "identity-service"
config.ServiceSecret = "identity-service-secret-abc123"
```

**Важно (v1.0+)**: Service authentication теперь опциональна для этих методов. Если `service_auth.enabled = true` на сервере, service authentication доступна но не обязательна (рекомендуется для production).

### JWT Authentication

Для методов, требующих JWT аутентификации (RevokeToken и все методы APIKeyService), требуется JWT токен:

```go
config.JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Для методов с опциональной аутентификацией (ValidateToken, ParseToken, ExtractClaims, ValidateBatch) можно использовать service auth или работать без аутентификации (особенно для localhost или если service_auth.enabled = false).

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

## Project ID (v1.0+)

`project_id` может быть указан в payload запроса или передается через gRPC metadata. Клиент автоматически устанавливает `project-id` в gRPC metadata из `config.ProjectID`, если `project_id` не указан в запросе.

**Priority:**
1. `project_id` in request payload (highest priority)
2. `project-id` in gRPC metadata (from `config.ProjectID`)
3. Legacy mode (if service has no projects configured)

### Example with project_id in payload:

```go
resp, err := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId: "user-123",
    ProjectId: "project-id", // Required (v1.0+)
})
```

### Example with project-id in metadata:

```go
config.ProjectID = "default-project-id" // Set in metadata as project-id
cl, _ := client.NewClient(config)

resp, err := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId: "user-123",
    ProjectId: "", // Empty - will use project-id from metadata
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
    ProjectId:       "project-id", // Required (v1.0+)
})
```

#### ValidateToken - Валидация токена

**Authentication опциональна (v1.0+)** - можно использовать service auth или работать без аутентификации (особенно для localhost):

```go
// Вариант 1: С service authentication (рекомендуется для production)
config.ServiceName = "gateway-service"
config.ServiceSecret = "gateway-service-secret"
cl, _ := client.NewClient(config)

// Вариант 2: Без аутентификации (для localhost или если service_auth.enabled = false)
cl, _ := client.NewClient(config)

// Валидация токена
// Токен в поле Token - это токен, который валидируется, а не токен для аутентификации запроса
resp, err := cl.ValidateToken(ctx, &authv1.ValidateTokenRequest{
    Token:          "jwt-token-to-validate",
    CheckBlacklist: true,
    ProjectId:      "project-id", // Required (v0.9.5+)
})

if resp.Valid {
    // Токен валиден
    claims := resp.Claims
    // Access standard fields directly (v0.9.5+)
    userID := claims.UserId
    projectID := claims.ProjectId
    deviceID := claims.DeviceId
    roles := claims.Roles
    email := claims.Email
    username := claims.Username
    
    // For service tokens
    sourceService := claims.SourceService
    targetService := claims.TargetService
    userIDInContext := claims.UserIdInContext
    // ...
}
```

#### RefreshToken - Обновление токена

```go
resp, err := cl.RefreshToken(ctx, &authv1.RefreshTokenRequest{
    RefreshToken: "refresh-token",
    ProjectId:    "project-id", // Required (v0.9.5+)
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

**Service authentication опциональна (v1.0+)**:

```go
// Настройка service authentication (опционально, рекомендуется для production)
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

**Примечание (v1.0+)**: Service authentication теперь опциональна. Если `service_auth.enabled = true` на сервере, service authentication доступна но не обязательна (рекомендуется для production).

#### Другие методы

- `RevokeToken` - отзыв токена (требует JWT аутентификации)
- `ParseToken` - парсинг токена без валидации (authentication опциональна, v1.0+)
- `ExtractClaims` - извлечение claims из токена (authentication опциональна, v1.0+)
- `ValidateBatch` - пакетная валидация токенов (authentication опциональна, v1.0+)

#### HealthCheck - Проверка здоровья сервиса

```go
resp, err := cl.HealthCheck(ctx)
if err != nil {
    log.Fatal(err)
}

switch resp.Status {
case "healthy":
    log.Printf("Service is healthy, version: %s, uptime: %d", resp.Version, resp.Uptime)
case "degraded":
    log.Printf("Service is degraded: %v", resp.Details)
case "unhealthy":
    log.Printf("Service is unhealthy: %v", resp.Details)
}
```

Возможные значения `Status`:
- `"healthy"` - сервис полностью работоспособен
- `"degraded"` - сервис работает, но с ограничениями (например, Redis недоступен)
- `"unhealthy"` - сервис не работает корректно

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
// Note: For v1.0+, it's recommended to always provide ProjectId in payload
// If ProjectId is empty, project-id from config.ProjectID will be used in metadata
resp, _ := cl.IssueToken(ctx, &authv1.IssueTokenRequest{
    UserId:    "user-123",
    ProjectId: "", // Empty - will use project-id from metadata (v1.0+)
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

## Migration Guide (v0.9.5)

### Breaking Changes: TokenClaims Structure

В версии 0.9.5 структура `TokenClaims` была обновлена: удалено поле `CustomClaims`, добавлены явные поля для всех стандартных claims.

#### До (v0.9.4 и ранее):

```go
if resp.Valid && resp.Claims != nil {
    // Доступ через map
    projectID := resp.Claims.CustomClaims["project_id"]
    deviceID := resp.Claims.CustomClaims["device_id"]
    roles := resp.Claims.CustomClaims["roles"]
    email := resp.Claims.CustomClaims["email"]
    username := resp.Claims.CustomClaims["username"]
}
```

#### После (v0.9.5+):

```go
if resp.Valid && resp.Claims != nil {
    // Прямой доступ к полям
    projectID := resp.Claims.ProjectId
    deviceID := resp.Claims.DeviceId
    roles := resp.Claims.Roles
    email := resp.Claims.Email
    username := resp.Claims.Username
    
    // Для service токенов
    sourceService := resp.Claims.SourceService
    targetService := resp.Claims.TargetService
    userIDInContext := resp.Claims.UserIdInContext
}
```

#### Миграция по полям:

| Старый способ (v0.9.4) | Новый способ (v0.9.5+) |
|------------------------|-------------------------|
| `claims.CustomClaims["project_id"]` | `claims.ProjectId` |
| `claims.CustomClaims["device_id"]` | `claims.DeviceId` |
| `claims.CustomClaims["roles"]` | `claims.Roles` |
| `claims.CustomClaims["email"]` | `claims.Email` |
| `claims.CustomClaims["username"]` | `claims.Username` |
| `claims.CustomClaims["source_service"]` | `claims.SourceService` |
| `claims.CustomClaims["target_service"]` | `claims.TargetService` |
| `claims.CustomClaims["user_id"]` (в service токенах) | `claims.UserIdInContext` |

#### Преимущества новой структуры:

- **Типобезопасность**: Поля имеют правильные типы (string, int64)
- **Производительность**: Нет необходимости в map lookup
- **Автодополнение**: IDE может предложить доступные поля
- **Документация**: Поля явно описаны в proto файле

## Репозиторий

- **GitHub:** [https://github.com/kabiroman/octawire-auth-service-go-client](https://github.com/kabiroman/octawire-auth-service-go-client)

## Лицензия

См. основной репозиторий проекта.

