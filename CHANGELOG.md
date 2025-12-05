# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.5] - 2025-12-05

### BREAKING CHANGES
- **TokenClaims structure updated**: Removed `CustomClaims` field, added explicit fields for standard claims
  - Removed: `CustomClaims map[string]string`
  - Added explicit fields: `ProjectId`, `DeviceId`, `Roles`, `Email`, `Username`, `SourceService`, `TargetService`, `UserIdInContext`
  - Migration: Update code from `claims.CustomClaims["project_id"]` to `claims.ProjectId`
  - Migration: Update code from `claims.CustomClaims["device_id"]` to `claims.DeviceId`
  - Migration: Update code from `claims.CustomClaims["roles"]` to `claims.Roles`
  - Migration: Update code from `claims.CustomClaims["email"]` to `claims.Email`
  - Migration: Update code from `claims.CustomClaims["username"]` to `claims.Username`
  - Migration: Update code from `claims.CustomClaims["source_service"]` to `claims.SourceService`
  - Migration: Update code from `claims.CustomClaims["target_service"]` to `claims.TargetService`
  - Migration: Update code from `claims.CustomClaims["user_id"]` (in service tokens) to `claims.UserIdInContext`

### Added
- Explicit fields in `TokenClaims` for all standard claims (16 fields total)
  - Standard JWT claims: `UserId`, `IssuedAt`, `ExpiresAt`, `Issuer`, `Audience`, `JwtId`
  - Required custom claims: `TokenType`, `ProjectId`, `KeyId`
  - Optional claims: `DeviceId`, `Roles`, `Email`, `Username`
  - Service token claims: `SourceService`, `TargetService`, `UserIdInContext`
- Updated examples to demonstrate usage of new explicit fields
- Enhanced integration tests to verify new fields in TokenClaims

### Updated
- Proto files synchronized with auth-service v0.9.5
- All examples updated to use new TokenClaims fields
- Integration tests updated to check new fields

### Removed
- `CustomClaims` map field from `TokenClaims` (replaced with explicit fields)

## [0.9.4] - 2025-12-01

### BREAKING CHANGES
- **Proto import path changed**: Import path changed from `github.com/kabiroman/octawire-auth-service/pkg/proto` to `github.com/kabiroman/octawire-auth-service-go-client/pkg/proto/auth/v1`
- Migration: Update all imports in your code to use the new path

### Added
- Embedded compiled proto files in `pkg/proto/auth/v1/` directory
- Client is now self-contained and does not require access to private auth-service repository

### Removed
- Dependency on `github.com/kabiroman/octawire-auth-service` (was private)
- `replace` directive in go.mod

### Fixed
- Client can now be used in external projects without access to private repositories

## [0.9.4] - 2025-12-01

### BREAKING CHANGES
- **HealthCheckResponse**: Поле `Healthy` (bool) заменено на `Status` (string)
  - Возможные значения Status: "healthy", "degraded", "unhealthy"
  - Добавлено поле `Timestamp` (int64) с Unix timestamp проверки
  - Миграция: `resp.Healthy` → `resp.Status == "healthy"`

### Изменено
- Обновлен для соответствия Auth Service v0.9.4 спецификации (GRPC_METHODS_1.0.json)
- Изменен ключ метаданных gRPC обратно на `project-id` (удалена поддержка `default-project-id`)
- Service authentication теперь опциональна для методов IssueServiceToken, ValidateToken, ParseToken, ExtractClaims, ValidateBatch

### Добавлено
- Константа `Version` для программного доступа к версии клиента
- Полная поддержка Auth Service Protocol v1.0:
  * Опциональная service authentication для методов валидации
  * Условная передача JWT токена только для методов, требующих JWT (RevokeToken, APIKeyService)
  * Поддержка `project-id` в gRPC metadata (v1.0+)
- Рефакторинг интеграционных тестов:
  * Переиспользуемые функции для тестирования различных сценариев
  * Тест `TestAllMethodsScenariosV1` покрывающий 4 сценария (TLS/no-TLS × auth/no-auth)
  * Автоматическое определение TLS требований сервера
  * Graceful skip для неподдерживаемых сценариев
- Обновлена документация TESTING.md:
  * Добавлен раздел о юнит-тестах с полным списком покрытия
  * Детальные инструкции по настройке и запуску интеграционных тестов
  * Инструкции по тестированию различных сценариев через Docker Compose
  * Переведена на русский язык

### Исправлено
- Удалена обратная совместимость с `default-project-id` (только `project-id` используется)
- Исправлена логика добавления JWT токена в metadata (только для требуемых методов)
- Улучшена обработка project_id в методах, где он не является частью protobuf сообщения

### Тестирование
- Рефакторинг интеграционных тестов для поддержки 4 различных сценариев
- Улучшена обработка JWT токенов для методов требующих JWT
- Добавлены юнит-тесты для проверки метаданных и аутентификации
- Обновлены примеры для соответствия v1.0 спецификации

### Соответствие спецификациям
- Полное соответствие спецификации GRPC_METHODS_1.0.md
- Соответствие требованиям Auth Service v1.0 по опциональной service authentication
- Корректная обработка JWT аутентификации только для требуемых методов

## [0.9.3] - 2025-01-28

### Изменено
- **BREAKING**: Изменен ключ метаданных gRPC с `project-id` на `default-project-id` (соответствие Auth Service v0.9.3)
- Обновлена версия клиента для работы с Auth Service v0.9.3
- Метод `IssueToken` теперь автоматически устанавливает `ProjectId` из конфигурации, если он не указан в запросе
- Методы валидации токенов (`ValidateToken`, `RefreshToken`, `RevokeToken`, `ParseToken`, `ExtractClaims`) теперь используют `project_id` из запроса для передачи в gRPC метаданные

### Добавлено
- Поддержка обязательного `project_id` в payload для всех методов работы с токенами (v0.9.3+)
- Автоматическая установка `default-project-id` в gRPC метаданные из `config.ProjectID`
- Секция "Project ID (v0.9.3+)" в README.md с объяснением приоритета разрешения `project_id`
- Улучшенное определение требования TLS в интеграционных тестах
- Поддержка legacy режима (пустой `project_id`) для совместимости с серверами без явной конфигурации проектов

### Исправлено
- Исправлена передача `project_id` в gRPC метаданные для методов валидации токенов
- Улучшена обработка TLS соединений в интеграционных тестах
- Обновлены все примеры для включения обязательного поля `ProjectId` в запросах

### Тестирование
- Добавлены интеграционные тесты для всех сценариев (PROD/DEV с service_auth=true/false)
- Протестирована работа с TLS и без TLS
- Протестирована работа в legacy режиме (пустой `project_id`)

### Соответствие спецификациям
- Полное соответствие спецификации GRPC_METHODS_1.0.md по использованию `default-project-id` в метаданных
- Полное соответствие требованиям Auth Service v0.9.3 по обязательности `project_id` в payload

## [0.9.2] - 2024-XX-XX

### Добавлено
- Базовая поддержка service authentication
- Поддержка TLS соединений
- Кэширование публичных ключей
- Retry логика для обработки временных ошибок

### Изменено
- Улучшена обработка ошибок
- Обновлена документация

## [0.9.1] - 2024-XX-XX

### Добавлено
- Первоначальный релиз Go клиента для Auth Service
- Поддержка всех основных методов JWT Service
- Поддержка API Key Service
- Примеры использования

[0.9.4]: https://github.com/kabiroman/octawire-auth-service-go-client/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/kabiroman/octawire-auth-service-go-client/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/kabiroman/octawire-auth-service-go-client/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/kabiroman/octawire-auth-service-go-client/releases/tag/v0.9.1

