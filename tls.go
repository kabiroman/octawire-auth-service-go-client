package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// LoadTLSConfig загружает TLS конфигурацию и создает gRPC credentials
func LoadTLSConfig(config *TLSConfig) (grpc.DialOption, error) {
	if config == nil || !config.Enabled {
		// Используем insecure соединение
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}

	var tlsConfig *tls.Config

	if config.InsecureSkipVerify {
		// Только для разработки - пропускаем проверку сертификата
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		// Загружаем CA сертификат для проверки сервера
		var certPool *x509.CertPool
		if config.CAFile != "" {
			caCert, err := os.ReadFile(config.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}

			certPool = x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
		} else {
			// Используем системный cert pool
			var err error
			certPool, err = x509.SystemCertPool()
			if err != nil {
				// Fallback на пустой pool
				certPool = x509.NewCertPool()
			}
		}

		tlsConfig = &tls.Config{
			RootCAs:    certPool,
			ServerName: config.ServerName,
		}
	}

	// Если указаны клиентские сертификаты, загружаем их для mTLS
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	creds := credentials.NewTLS(tlsConfig)
	return grpc.WithTransportCredentials(creds), nil
}

