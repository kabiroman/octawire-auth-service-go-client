package client

import (
	"time"
)

// ClientConfig содержит конфигурацию клиента
type ClientConfig struct {
	// Address - адрес сервера (host:port)
	Address string

	// TLS - настройки TLS
	TLS *TLSConfig

	// APIKey - API ключ для аутентификации (опционально)
	APIKey string

	// ServiceName - имя сервиса для service authentication (опционально, требуется для IssueServiceToken)
	ServiceName string

	// ServiceSecret - секрет сервиса для service authentication (опционально, требуется для IssueServiceToken)
	ServiceSecret string

	// JWTToken - JWT токен для методов, требующих JWT аутентификации (опционально)
	JWTToken string

	// ProjectID - дефолтный project_id
	ProjectID string

	// Retry - настройки retry
	Retry *RetryConfig

	// KeyCache - настройки кэша ключей
	KeyCache *KeyCacheConfig

	// Timeout - таймауты для запросов
	Timeout *TimeoutConfig
}

// TLSConfig содержит настройки TLS/mTLS
type TLSConfig struct {
	// Enabled - включен ли TLS
	Enabled bool

	// CertFile - путь к файлу клиентского сертификата (для mTLS)
	CertFile string

	// KeyFile - путь к файлу приватного ключа клиента (для mTLS)
	KeyFile string

	// CAFile - путь к файлу CA сертификата
	CAFile string

	// ServerName - имя сервера для проверки сертификата (SNI)
	ServerName string

	// InsecureSkipVerify - пропустить проверку сертификата (только для разработки)
	InsecureSkipVerify bool
}

// RetryConfig содержит настройки retry логики
type RetryConfig struct {
	// MaxAttempts - максимальное количество попыток (включая первую)
	MaxAttempts int

	// InitialBackoff - начальная задержка перед повтором (в миллисекундах)
	InitialBackoff time.Duration

	// MaxBackoff - максимальная задержка перед повтором
	MaxBackoff time.Duration
}

// KeyCacheConfig содержит настройки кэша ключей
type KeyCacheConfig struct {
	// TTL - время жизни ключа в кэше (по умолчанию используется cache_until из ответа)
	TTL time.Duration

	// MaxSize - максимальное количество проектов в кэше (0 = без ограничения)
	MaxSize int
}

// TimeoutConfig содержит настройки таймаутов
type TimeoutConfig struct {
	// Connect - таймаут подключения
	Connect time.Duration

	// Request - таймаут запроса
	Request time.Duration
}

// DefaultConfig возвращает конфигурацию с настройками по умолчанию
func DefaultConfig(address string) *ClientConfig {
	return &ClientConfig{
		Address: address,
		TLS: &TLSConfig{
			Enabled: false,
		},
		Retry: &RetryConfig{
			MaxAttempts:    3,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     5 * time.Second,
		},
		KeyCache: &KeyCacheConfig{
			TTL:     0, // Используется cache_until из ответа
			MaxSize: 100,
		},
		Timeout: &TimeoutConfig{
			Connect: 10 * time.Second,
			Request: 30 * time.Second,
		},
	}
}

