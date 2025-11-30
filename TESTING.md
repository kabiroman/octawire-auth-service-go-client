# Руководство по тестированию

Этот документ описывает, как тестировать Go-клиент для Auth Service в различных сценариях.

## Типы тестов

Клиент включает два типа тестов:

1. **Юнит-тесты** (`client_test.go`) - тестирование компонентов клиента без реального сервиса
2. **Интеграционные тесты** (`integration_test.go`) - тестирование клиента против реального Auth Service

## Юнит-тесты

Юнит-тесты проверяют логику клиента изолированно, используя моки для gRPC клиента. Эти тесты не требуют запущенного сервиса и выполняются быстро.

### Запуск юнит-тестов

```bash
cd services/auth-service/clients/octawire-auth-service-go-client

# Запустить все юнит-тесты
go test -v ./...

# Запустить только юнит-тесты (без интеграционных)
go test -v -short ./...

# Запустить конкретный тест
go test -v -run TestValidateTokenWithoutAuth
```

### Покрытие юнит-тестов

Юнит-тесты покрывают следующие аспекты:

#### Обработка ошибок
- ✅ `TestErrorHandling` - обработка различных типов ошибок
- ✅ `TestWrapError` - обёртка ошибок клиента
- ✅ `TestWrapErrorPermissionDenied` - обработка ошибок доступа
- ✅ `TestWrapErrorUnauthenticated` - обработка ошибок аутентификации

#### Кэширование ключей
- ✅ `TestKeyCache` - кэширование публичных ключей

#### Retry логика
- ✅ `TestRetryLogic` - повторные попытки при ошибках
- ✅ `TestRetryLogicNonRetryable` - пропуск повторных попыток для некритичных ошибок

#### Конфигурация
- ✅ `TestDefaultConfig` - значения конфигурации по умолчанию

#### Методы клиента
- ✅ `TestClientIssueToken` - выдача токенов
- ✅ `TestClientGetPublicKeyWithCache` - получение публичного ключа с кэшем

#### Аутентификация
- ✅ `TestIssueServiceTokenWithServiceAuth` - выдача service токена с аутентификацией
- ✅ `TestIssueServiceTokenWithoutServiceAuth` - выдача service токена без аутентификации
- ✅ `TestValidateTokenWithJWT` - валидация токена с JWT
- ✅ `TestValidateTokenWithoutAuth` - валидация токена без аутентификации
- ✅ `TestValidateTokenWithoutJWT` - валидация токена без JWT токена

#### Метаданные
- ✅ `TestMetadataProjectID` - добавление project-id в метаданные
- ✅ `TestMetadataJWTOnlyForRequiredMethods` - добавление JWT только для требуемых методов
- ✅ `TestMetadataServiceAuth` - добавление service authentication в метаданные

#### JWT требования
- ✅ `TestRevokeTokenRequiresJWT` - проверка требования JWT для RevokeToken
- ✅ `TestAPIKeyMethodsRequireJWT` - проверка требования JWT для методов APIKeyService

### Пример вывода юнит-тестов

```
=== RUN   TestValidateTokenWithoutAuth
=== RUN   TestValidateTokenWithoutAuth/Without_Auth
--- PASS: TestValidateTokenWithoutAuth (0.00s)
    --- PASS: TestValidateTokenWithoutAuth/Without_Auth (0.00s)
PASS
ok  	github.com/kabiroman/octawire-auth-service-go-client	0.015s
```

## Интеграционные тесты

Интеграционные тесты проверяют клиент против реального запущенного Auth Service. Они тестируют различные сценарии конфигурации: с TLS и без, с service authentication и без.

### Сценарии тестирования

Клиент тестируется в 4 различных сценариях:

#### Сценарий 1: Без TLS и без аутентификации
- **TLS**: Отключен
- **Service Auth**: Отключен
- **Ожидаемое поведение**:
  - Публичные методы работают (IssueToken, RefreshToken, GetPublicKey, HealthCheck)
  - Методы с опциональной аутентификацией работают (ValidateToken, ParseToken, ExtractClaims, ValidateBatch)
  - IssueServiceToken может не работать (требуется service auth)
  - Методы требующие JWT требуют JWT токен (RevokeToken, CreateAPIKey)

#### Сценарий 2: Без TLS, с Service Authentication
- **TLS**: Отключен
- **Service Auth**: Включен
- **Ожидаемое поведение**:
  - Публичные методы работают
  - IssueServiceToken работает с валидной service auth
  - IssueServiceToken не работает без service auth

#### Сценарий 3: С TLS, без аутентификации
- **TLS**: Включен
- **Service Auth**: Отключен
- **Ожидаемое поведение**:
  - Все методы работают через TLS соединение
  - Требуется корректная конфигурация TLS на сервере

#### Сценарий 4: С TLS и с Service Authentication
- **TLS**: Включен
- **Service Auth**: Включен
- **Ожидаемое поведение**:
  - Все методы работают через TLS соединение
  - IssueServiceToken работает с валидной service auth через TLS

### Настройка окружения для интеграционных тестов

#### 1. Запуск Auth Service через Docker Compose

Самый простой способ - использовать Docker Compose:

```bash
cd services/auth-service

# Запустить все зависимости (Redis, PostgreSQL)
docker-compose up -d redis postgres

# Запустить Auth Service (dev режим, без TLS, без service auth)
docker-compose --profile dev up -d auth-service-dev

# Проверить статус
docker-compose ps

# Просмотр логов
docker-compose logs -f auth-service-dev
```

#### 2. Конфигурация сервиса

Для тестирования разных сценариев можно изменить конфигурацию в `services/auth-service/config/config.json`:

**Базовые настройки для тестов без TLS и без auth:**
```json
{
  "security": {
    "auth_required": false,
    "service_auth": {
      "enabled": false
    }
  },
  "tls": {
    "enabled": false
  }
}
```

**Для тестов с service auth:**
```json
{
  "security": {
    "auth_required": false,
    "service_auth": {
      "enabled": true,
      "services": {
        "identity-service": {
          "secret": "identity-service-secret-abc123def456"
        }
      }
    }
  },
  "tls": {
    "enabled": false
  }
}
```

**Для тестов с TLS:**
```json
{
  "tls": {
    "enabled": true,
    "cert_file": "/app/config/tls/cert.pem",
    "key_file": "/app/config/tls/key.pem"
  }
}
```

#### 3. Перезапуск сервиса после изменения конфигурации

```bash
cd services/auth-service

# Остановить сервис
docker-compose stop auth-service-dev

# Обновить конфигурацию в config/config.json

# Запустить снова
docker-compose start auth-service-dev

# Или пересоздать контейнер
docker-compose up -d --force-recreate auth-service-dev
```

### Запуск интеграционных тестов

#### Базовый запуск

```bash
cd services/auth-service/clients/octawire-auth-service-go-client

# Запустить все интеграционные тесты
go test -v -integration=true -service-address=localhost:50051

# Запустить только тест без TLS и без auth
go test -v -integration=true -run TestAllMethodsWithoutTLSAndAuth -service-address=localhost:50051

# Запустить тест всех сценариев
go test -v -integration=true -run TestAllMethodsScenariosV1 -service-address=localhost:50051
```

#### Доступные флаги

- `-integration=true` - включить интеграционные тесты (по умолчанию пропускаются)
- `-service-address=HOST:PORT` - адрес Auth Service (по умолчанию `localhost:50051`)
- `-api-key=KEY` - API ключ для аутентификации (опционально)

### Структура интеграционных тестов

#### TestAllMethodsWithoutTLSAndAuth

Простой тест, который проверяет все методы без TLS и без аутентификации:

```bash
go test -v -integration=true -run TestAllMethodsWithoutTLSAndAuth -service-address=localhost:50051
```

Этот тест проверяет:
- HealthCheck
- IssueToken
- ValidateToken
- RefreshToken
- ParseToken
- ExtractClaims
- ValidateBatch
- GetPublicKey
- IssueServiceToken
- RevokeToken
- CreateAPIKey

#### TestAllMethodsScenariosV1

Комплексный тест, который автоматически проверяет все 4 сценария:

```bash
go test -v -integration=true -run TestAllMethodsScenariosV1 -service-address=localhost:50051
```

Этот тест:
- Автоматически определяет, требуется ли TLS на сервере
- Пропускает TLS-сценарии, если сервер не поддерживает TLS
- Создаёт JWT токен для методов, требующих JWT
- Выполняет все тесты методов для каждого доступного сценария

### Пример вывода интеграционных тестов

```
=== RUN   TestAllMethodsScenariosV1
=== RUN   TestAllMethodsScenariosV1/NoTLS_NoAuth
    integration_test.go:757: Testing scenario: NoTLS_NoAuth (TLS=false, ServiceAuth=false)
=== RUN   TestAllMethodsScenariosV1/NoTLS_NoAuth/HealthCheck
    integration_test.go:63: HealthCheck: version=v0.9.0-dev, uptime=1709
=== RUN   TestAllMethodsScenariosV1/NoTLS_NoAuth/IssueToken
    integration_test.go:77: IssueToken: access_token length=622, expires_at=1764539168
...
--- PASS: TestAllMethodsScenariosV1 (0.10s)
    --- PASS: TestAllMethodsScenariosV1/NoTLS_NoAuth (0.04s)
    --- PASS: TestAllMethodsScenariosV1/NoTLS_WithServiceAuth (0.05s)
    --- SKIP: TestAllMethodsScenariosV1/WithTLS_NoAuth (0.00s)
    --- SKIP: TestAllMethodsScenariosV1/WithTLS_WithServiceAuth (0.00s)
PASS
```

## Тестирование различных сценариев

### Сценарий 1: Без TLS и без auth

**Настройка сервиса:**
1. Убедитесь, что `config/config.json` содержит:
   ```json
   {
     "security": {
       "auth_required": false,
       "service_auth": {
         "enabled": false
       }
     },
     "tls": {
       "enabled": false
     }
   }
   ```

2. Запустите сервис:
   ```bash
   docker-compose --profile dev up -d auth-service-dev
   ```

**Запуск тестов:**
```bash
go test -v -integration=true -run TestAllMethodsWithoutTLSAndAuth -service-address=localhost:50051
```

### Сценарий 2: Без TLS, с Service Auth

**Настройка сервиса:**
1. Измените `config/config.json`:
   ```json
   {
     "security": {
       "auth_required": false,
       "service_auth": {
         "enabled": true,
         "services": {
           "identity-service": {
             "secret": "identity-service-secret-abc123def456"
           }
         }
       }
     },
     "tls": {
       "enabled": false
     }
   }
   ```

2. Перезапустите сервис:
   ```bash
   docker-compose restart auth-service-dev
   ```

**Запуск тестов:**
```bash
go test -v -integration=true -run TestAllMethodsScenariosV1 -service-address=localhost:50051
```

### Сценарий 3 и 4: С TLS

Для тестирования сценариев с TLS необходимо:

1. Создать TLS сертификаты:
   ```bash
   cd services/auth-service
   mkdir -p config/tls
   
   openssl req -x509 -newkey rsa:4096 -keyout config/tls/key.pem \
     -out config/tls/cert.pem -days 365 -nodes \
     -subj "/CN=localhost"
   ```

2. Обновить `config/config.json`:
   ```json
   {
     "tls": {
       "enabled": true,
       "cert_file": "/app/config/tls/cert.pem",
       "key_file": "/app/config/tls/key.pem"
     }
   }
   ```

3. Обновить `docker-compose.yml` для монтирования сертификатов:
   ```yaml
   volumes:
     - ./config:/app/config:ro
     - ./config/tls:/app/config/tls:ro
   ```

4. Перезапустить сервис:
   ```bash
   docker-compose up -d --force-recreate auth-service-dev
   ```

5. Запустить тесты:
   ```bash
   go test -v -integration=true -run TestAllMethodsScenariosV1 -service-address=localhost:50051
   ```

## Устранение неполадок

### Сервис не запускается

**Проблема**: Сервис сразу завершается или не запускается

**Решения**:
1. Проверьте, запущен ли Redis:
   ```bash
   docker-compose ps redis
   # или
   redis-cli ping
   ```

2. Проверьте, доступны ли порты:
   ```bash
   # gRPC порт
   lsof -i :50051
   # HTTP порт (health check)
   lsof -i :9765
   ```

3. Проверьте логи сервиса:
   ```bash
   docker-compose logs auth-service-dev
   ```

4. Проверьте конфигурацию:
   ```bash
   # Проверить синтаксис JSON
   jq . services/auth-service/config/config.json
   ```

### Ошибки TLS в сценариях с TLS

**Проблема**: Сервис не запускается с ошибками TLS

**Решения**:
1. Убедитесь, что сертификаты существуют:
   ```bash
   ls -la services/auth-service/config/tls/
   ```

2. Проверьте пути к сертификатам в конфигурации:
   ```json
   {
     "tls": {
       "enabled": true,
       "cert_file": "/app/config/tls/cert.pem",
       "key_file": "/app/config/tls/key.pem"
     }
   }
   ```

3. Убедитесь, что сертификаты смонтированы в Docker контейнер:
   ```bash
   docker-compose exec auth-service-dev ls -la /app/config/tls/
   ```

### Ошибки подключения клиента

**Проблема**: Клиент не может подключиться к сервису

**Решения**:
1. Проверьте, что сервис запущен:
   ```bash
   curl http://localhost:9765/health
   # или
   docker-compose ps
   ```

2. Проверьте адрес сервиса:
   - По умолчанию: `localhost:50051` для gRPC
   - Для Docker: может потребоваться использовать IP контейнера

3. Для TLS: убедитесь, что клиент использует `InsecureSkipVerify: true` для тестов с самоподписанными сертификатами

### Ошибки аутентификации

**Проблема**: Методы завершаются с ошибками аутентификации

**Решения**:
1. **Service Auth ошибки**:
   - Проверьте, что `ServiceName` и `ServiceSecret` установлены в конфигурации клиента
   - Проверьте, что имя сервиса есть в `allowed_services` в конфигурации сервера
   - Проверьте, что секрет совпадает с конфигурацией сервера

2. **JWT Auth ошибки**:
   - Проверьте, что `JWTToken` установлен в конфигурации клиента
   - Проверьте, что токен валиден и не истёк
   - Проверьте, что токен был выдан тем же сервисом

### Ошибки компиляции тестов

**Проблема**: `go test` завершается с ошибками компиляции

**Решения**:
1. Убедитесь, что вы в правильной директории:
   ```bash
   cd services/auth-service/clients/octawire-auth-service-go-client
   ```

2. Обновите зависимости:
   ```bash
   go mod tidy
   ```

3. Проверьте версию Go (требуется Go 1.21+):
   ```bash
   go version
   ```

## Непрерывная интеграция

Для CI/CD пайплайнов можно использовать:

```bash
# Запустить только юнит-тесты (быстро, не требует сервиса)
go test -short -v ./...

# Запустить интеграционные тесты (требует запущенный сервис)
go test -v -integration=true -service-address=localhost:50051 ./...
```

## Дополнительные ресурсы

- [README клиента](./README.md) - документация по использованию клиента
- [Спецификация gRPC методов](../../docs/protocol/GRPC_METHODS_1.0.md) - полная справочная документация API
- [Руководство по безопасности](../../docs/SECURITY.md) - лучшие практики безопасности
