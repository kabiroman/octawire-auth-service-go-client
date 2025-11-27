package client

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
)

// Предопределенные ошибки клиента
var (
	ErrConnectionFailed  = errors.New("connection failed")
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrServiceAuthFailed = errors.New("service authentication failed")
)

// ClientError представляет ошибку клиента с дополнительной информацией
type ClientError struct {
	Code    authv1.ErrorCode
	Message string
	Err     error
}

func (e *ClientError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("client error: code=%d", e.Code)
}

func (e *ClientError) Unwrap() error {
	return e.Err
}

// WrapError оборачивает gRPC ошибку в понятный тип ошибки клиента
func WrapError(err error) error {
	if err == nil {
		return nil
	}

	// Проверяем, является ли это gRPC статус ошибкой
	st, ok := status.FromError(err)
	if !ok {
		// Если это не gRPC ошибка, проверяем на ошибки подключения/TLS
		errStr := err.Error()
		errLower := strings.ToLower(errStr)
		
		// Проверяем на типичные ошибки TLS/подключения
		if strings.Contains(errLower, "tls") || strings.Contains(errLower, "certificate") ||
			strings.Contains(errLower, "connection refused") || strings.Contains(errLower, "no such host") ||
			strings.Contains(errLower, "timeout") || strings.Contains(errLower, "dial") {
			return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
		}
		
		// Если это не gRPC ошибка, возвращаем как есть
		return err
	}

	// Обрабатываем коды ошибок
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		msg := st.Message()
		msgLower := strings.ToLower(msg)
		
		// Проверяем на специфичные ошибки подключения
		if strings.Contains(msgLower, "tls") || strings.Contains(msgLower, "certificate") ||
			strings.Contains(msgLower, "connection refused") || strings.Contains(msgLower, "no such host") {
			return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
		}
		
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	case codes.ResourceExhausted:
		return fmt.Errorf("%w: %v", ErrRateLimitExceeded, err)
	case codes.PermissionDenied:
		// Проверяем, является ли это ошибкой service authentication
		msg := st.Message()
		msgLower := strings.ToLower(msg)
		if strings.Contains(msgLower, "service authentication") || strings.Contains(msgLower, "service-name") || strings.Contains(msgLower, "service-secret") {
			return &ClientError{
				Code:    authv1.ErrorCode_ERROR_UNKNOWN,
				Message: msg,
				Err:     fmt.Errorf("%w: %v", ErrServiceAuthFailed, err),
			}
		}
		// Общая ошибка PermissionDenied
		return &ClientError{
			Code:    authv1.ErrorCode_ERROR_UNKNOWN,
			Message: msg,
			Err:     err,
		}
	case codes.Unauthenticated:
		// JWT authentication failed
		return &ClientError{
			Code:    authv1.ErrorCode_ERROR_UNKNOWN,
			Message: st.Message(),
			Err:     err,
		}
	}

	// Пытаемся извлечь ErrorCode из деталей ответа
	// Если в ответе есть ErrorCode, используем его
	// В противном случае используем код gRPC статуса

	// Проверяем, есть ли в деталях ErrorCode
	// Это зависит от того, как сервер возвращает ошибки
	// Обычно ErrorCode передается в метаданных или в деталях ответа

	// Для простоты, если это ошибка валидации токена, проверяем сообщение
	msg := st.Message()
	msgLower := strings.ToLower(msg)
	if strings.Contains(msgLower, "invalid token") || strings.Contains(msgLower, "invalid signature") {
		return &ClientError{
			Code:    authv1.ErrorCode_ERROR_INVALID_TOKEN,
			Message: msg,
			Err:     err,
		}
	}
	if strings.Contains(msgLower, "expired") {
		return &ClientError{
			Code:    authv1.ErrorCode_ERROR_EXPIRED_TOKEN,
			Message: msg,
			Err:     err,
		}
	}
	if strings.Contains(msgLower, "revoked") {
		return &ClientError{
			Code:    authv1.ErrorCode_ERROR_TOKEN_REVOKED,
			Message: msg,
			Err:     err,
		}
	}

	// Возвращаем обернутую ошибку
	return fmt.Errorf("grpc error [%s]: %s", st.Code(), msg)
}

// ErrorFromCode создает ошибку из ErrorCode
func ErrorFromCode(code authv1.ErrorCode, message string) error {
	switch code {
	case authv1.ErrorCode_ERROR_INVALID_TOKEN, authv1.ErrorCode_ERROR_INVALID_SIGNATURE:
		return &ClientError{
			Code:    code,
			Message: message,
			Err:     ErrInvalidToken,
		}
	case authv1.ErrorCode_ERROR_EXPIRED_TOKEN:
		return &ClientError{
			Code:    code,
			Message: message,
			Err:     ErrTokenExpired,
		}
	case authv1.ErrorCode_ERROR_TOKEN_REVOKED:
		return &ClientError{
			Code:    code,
			Message: message,
			Err:     ErrTokenRevoked,
		}
	case authv1.ErrorCode_ERROR_RATE_LIMIT_EXCEEDED:
		return &ClientError{
			Code:    code,
			Message: message,
			Err:     ErrRateLimitExceeded,
		}
	default:
		return &ClientError{
			Code:    code,
			Message: message,
		}
	}
}

// IsRetryableError проверяет, можно ли повторить запрос при этой ошибке
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}


