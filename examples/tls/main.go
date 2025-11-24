package main

import (
	"context"
	"fmt"
	"log"

	"github.com/kabiroman/octawire-auth-service"
	authv1 "github.com/octawire/auth-service/internal/proto"
)

func main() {
	// Создаем конфигурацию с TLS
	config := client.DefaultConfig("localhost:50051")
	config.ProjectID = "default-project-id"

	// Настраиваем TLS
	config.TLS = &client.TLSConfig{
		Enabled:  true,
		CAFile:   "/path/to/ca.crt",           // Путь к CA сертификату
		CertFile: "/path/to/client.crt",      // Путь к клиентскому сертификату (для mTLS)
		KeyFile:  "/path/to/client.key",      // Путь к приватному ключу клиента (для mTLS)
		ServerName: "auth-service.example.com", // Имя сервера для SNI
	}

	// Для разработки можно использовать InsecureSkipVerify (НЕ для продакшена!)
	// config.TLS.InsecureSkipVerify = true

	// Создаем клиент
	cl, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer cl.Close()

	ctx := context.Background()

	// Пример использования с TLS
	fmt.Println("=== IssueToken with TLS ===")
	issueReq := &authv1.IssueTokenRequest{
		UserId: "user-123",
	}

	issueResp, err := cl.IssueToken(ctx, issueReq)
	if err != nil {
		log.Fatalf("Failed to issue token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", issueResp.AccessToken)
	fmt.Printf("Key ID: %s\n", issueResp.KeyId)

	// Health Check
	fmt.Println("\n=== HealthCheck ===")
	healthResp, err := cl.HealthCheck(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}

	fmt.Printf("Service is healthy: %v\n", healthResp.Healthy)
	fmt.Printf("Version: %s\n", healthResp.Version)
}

