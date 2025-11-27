# Testing Guide

This document describes how to test the Go client against Auth Service in different scenarios.

## Test Scenarios

The client is tested against Auth Service in 4 different scenarios:

### Scenario 1: DEV + service_auth=false
- **Environment**: `PRODUCTION` not set or `false`
- **Config**: `service_auth.enabled = false`
- **TLS**: Optional (can be disabled)
- **Expected Behavior**:
  - Public methods work (IssueToken, RefreshToken, GetPublicKey, HealthCheck)
  - IssueServiceToken fails (service auth required but disabled)
  - JWT methods require JWT token

### Scenario 2: DEV + service_auth=true
- **Environment**: `PRODUCTION` not set or `false`
- **Config**: `service_auth.enabled = true`
- **TLS**: Optional (can be disabled)
- **Expected Behavior**:
  - Public methods work
  - IssueServiceToken works with valid service auth
  - IssueServiceToken fails without service auth
  - JWT methods require JWT token

### Scenario 3: PROD + service_auth=false
- **Environment**: `PRODUCTION=true`
- **Config**: `service_auth.enabled = false`
- **TLS**: Recommended but not mandatory
- **Expected Behavior**:
  - Public methods work
  - IssueServiceToken fails (service auth required but disabled)
  - JWT methods require JWT token

### Scenario 4: PROD + service_auth=true
- **Environment**: `PRODUCTION=true`
- **Config**: `service_auth.enabled = true`
- **TLS**: **Mandatory** for both gRPC and TCP
- **Expected Behavior**:
  - Public methods work (with TLS)
  - IssueServiceToken works with valid service auth (with TLS)
  - IssueServiceToken fails without service auth
  - JWT methods require JWT token (with TLS)

## Running Tests

### Prerequisites

1. **Auth Service** must be built:
   ```bash
   cd services/auth-service
   go build -o bin/auth-service ./cmd/auth-service
   ```

2. **Test configurations** must exist in `services/auth-service/config/`:
   - `config.dev.service_auth_false.json`
   - `config.dev.service_auth_true.json`
   - `config.prod.service_auth_false.json`
   - `config.prod.service_auth_true.json`

3. **Redis** must be running (for blacklist and caching):
   ```bash
   redis-server
   ```

4. **JWT keys** must exist (if using TLS in PROD scenarios):
   - `/etc/jwt/private.pem`
   - `/etc/jwt/public.pem`
   - `/etc/jwt/tls/cert.pem` (for TLS)
   - `/etc/jwt/tls/key.pem` (for TLS)

### Automated Testing

Run all scenarios automatically:

```bash
cd services/auth-service
./scripts/test-client-scenarios.sh
```

The script will:
1. Start service with each configuration
2. Run test client for each scenario
3. Collect results
4. Stop service
5. Report summary

### Manual Testing

#### 1. Start Service

For DEV scenarios:
```bash
cd services/auth-service
PRODUCTION=false ./bin/auth-service -config config/config.dev.service_auth_true.json
```

For PROD scenarios:
```bash
cd services/auth-service
PRODUCTION=true ./bin/auth-service -config config/config.prod.service_auth_true.json
```

#### 2. Run Test Client

```bash
cd services/auth-service/clients/octawire-auth-service-go-client/examples/test-scenarios
go run main.go -scenario dev-sa-true
```

Available scenarios:
- `dev-sa-false` - DEV with service_auth disabled
- `dev-sa-true` - DEV with service_auth enabled
- `prod-sa-false` - PROD with service_auth disabled
- `prod-sa-true` - PROD with service_auth enabled

## Test Cases

The test program covers:

### Public Methods (No Authentication Required)
- ✅ `IssueToken` - Issue new JWT token
- ✅ `RefreshToken` - Refresh token
- ✅ `GetPublicKey` - Get public key
- ✅ `HealthCheck` - Health check

### Service Authentication Methods
- ✅ `IssueServiceToken` with valid service auth - should work
- ✅ `IssueServiceToken` without service auth - should fail
- ✅ `IssueServiceToken` with invalid service auth - should fail

### JWT Authentication Methods
- ✅ `ValidateToken` with JWT token - should work
- ✅ `ValidateToken` without JWT token - should fail
- ✅ `ParseToken` with JWT token - should work
- ✅ `ExtractClaims` with JWT token - should work
- ✅ `RevokeToken` with JWT token - should work
- ✅ `ValidateBatch` with JWT token - should work

### APIKeyService Methods (All Require JWT)
- ✅ `CreateAPIKey` with JWT token - should work
- ✅ `ValidateAPIKey` with JWT token - should work
- ✅ `ListAPIKeys` with JWT token - should work

### Error Handling
- ✅ `ErrServiceAuthFailed` is returned correctly
- ✅ `PermissionDenied` errors are handled
- ✅ `Unauthenticated` errors are handled

## Expected Results Matrix

| Scenario | IssueServiceToken (no auth) | IssueServiceToken (with auth) | JWT Methods (no token) | JWT Methods (with token) |
|----------|----------------------------|-------------------------------|------------------------|--------------------------|
| DEV + sa=false | ❌ Fail (service auth required) | ❌ Fail (service auth disabled) | ❌ Fail | ✅ Pass |
| DEV + sa=true | ❌ Fail (service auth required) | ✅ Pass | ❌ Fail | ✅ Pass |
| PROD + sa=false | ❌ Fail (service auth required) | ❌ Fail (service auth disabled) | ❌ Fail | ✅ Pass |
| PROD + sa=true | ❌ Fail (service auth required) | ✅ Pass (TLS required) | ❌ Fail | ✅ Pass (TLS required) |

## Troubleshooting

### Service Fails to Start

**Problem**: Service exits immediately or fails to start

**Solutions**:
1. Check if Redis is running:
   ```bash
   redis-cli ping
   ```

2. Check if ports are available:
   ```bash
   # gRPC port
   lsof -i :50051
   # TCP port
   lsof -i :50052
   # HTTP port
   lsof -i :9765
   ```

3. Check service logs:
   ```bash
   cat /tmp/auth-service.log
   ```

4. Verify config file is valid JSON:
   ```bash
   jq . config/config.dev.service_auth_true.json
   ```

### TLS Errors in PROD Scenarios

**Problem**: Service fails to start with TLS errors in PROD scenarios

**Solutions**:
1. Ensure TLS certificates exist:
   ```bash
   ls -la /etc/jwt/tls/
   ```

2. For testing, you can generate self-signed certificates:
   ```bash
   mkdir -p /etc/jwt/tls
   openssl req -x509 -newkey rsa:4096 -keyout /etc/jwt/tls/key.pem \
     -out /etc/jwt/tls/cert.pem -days 365 -nodes \
     -subj "/CN=localhost"
   ```

3. Update config to point to correct certificate paths

### Client Connection Errors

**Problem**: Client cannot connect to service

**Solutions**:
1. Verify service is running:
   ```bash
   curl http://localhost:9765/health
   ```

2. Check if using correct address:
   - Default: `localhost:50051` for gRPC
   - For TLS: ensure client TLS config matches server

3. Check firewall/network settings

### Authentication Failures

**Problem**: Methods fail with authentication errors

**Solutions**:
1. **Service Auth Failures**:
   - Verify `ServiceName` and `ServiceSecret` are set in client config
   - Verify service name is in `allowed_services` in server config
   - Verify secret matches server config

2. **JWT Auth Failures**:
   - Verify `JWTToken` is set in client config
   - Verify token is valid and not expired
   - Verify token was issued by the same service

### Test Client Compilation Errors

**Problem**: `go run main.go` fails with compilation errors

**Solutions**:
1. Ensure you're in the correct directory:
   ```bash
   cd services/auth-service/clients/octawire-auth-service-go-client/examples/test-scenarios
   ```

2. Update dependencies:
   ```bash
   cd services/auth-service/clients/octawire-auth-service-go-client
   go mod tidy
   ```

3. Check Go version (requires Go 1.24+):
   ```bash
   go version
   ```

## Test Output

The test program outputs results for each test case:

```
=== Test Results for Scenario: dev-sa-true ===
✅ IssueToken: PASSED - Token issued, key_id: key-1
✅ RefreshToken: PASSED - Token refreshed successfully
✅ GetPublicKey: PASSED - Key retrieved, algorithm: RS256
✅ HealthCheck: PASSED - Service healthy: true, version: 0.9.2
✅ IssueServiceToken (no auth): PASSED - Correctly failed with client error
✅ IssueServiceToken (with auth): PASSED - Service token issued successfully
...

Summary: 17 passed, 0 failed
```

## Continuous Integration

For CI/CD pipelines, you can run:

```bash
cd services/auth-service
./scripts/test-client-scenarios.sh
```

The script exits with code 0 if all tests pass, or 1 if any test fails.

## Additional Resources

- [Client README](../README.md) - Client usage documentation
- [gRPC Methods Specification](../../../docs/protocol/GRPC_METHODS_1.0.md) - Complete API reference
- [Security Guide](../../../docs/SECURITY.md) - Security best practices

