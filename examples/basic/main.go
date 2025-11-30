package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kabiroman/octawire-auth-service-go-client"
	authv1 "github.com/kabiroman/octawire-auth-service/pkg/proto"
)

func main() {
	// Создаем конфигурацию клиента
	config := client.DefaultConfig("localhost:50051")
	config.ProjectID = "default-project-id"

	// Создаем клиент
	cl, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer cl.Close()

	ctx := context.Background()

	// Пример 1: Выдача токена
	fmt.Println("=== IssueToken ===")
	issueReq := &authv1.IssueTokenRequest{
		UserId:    "user-123",
		ProjectId: "default-project-id", // Required (v0.9.3+)
		Claims: map[string]string{
			"role": "admin",
		},
		AccessTokenTtl:  3600,  // 1 час
		RefreshTokenTtl: 86400, // 24 часа
	}

	issueResp, err := cl.IssueToken(ctx, issueReq)
	if err != nil {
		log.Fatalf("Failed to issue token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", issueResp.AccessToken)
	fmt.Printf("Refresh Token: %s\n", issueResp.RefreshToken)
	fmt.Printf("Access Token Expires At: %s\n", time.Unix(issueResp.AccessTokenExpiresAt, 0))
	fmt.Printf("Refresh Token Expires At: %s\n", time.Unix(issueResp.RefreshTokenExpiresAt, 0))
	fmt.Printf("Key ID: %s\n", issueResp.KeyId)

	// Пример 2: Валидация токена (требует JWT токен в конфигурации)
	fmt.Println("\n=== ValidateToken ===")
	// Создаем клиент с JWT токеном для валидации
	jwtConfig := client.DefaultConfig("localhost:50051")
	jwtConfig.ProjectID = "default-project-id"
	jwtConfig.JWTToken = issueResp.AccessToken // Используем выданный токен как JWT для аутентификации

	jwtClient, err := client.NewClient(jwtConfig)
	if err != nil {
		log.Fatalf("Failed to create JWT client: %v", err)
	}
	defer jwtClient.Close()

	validateReq := &authv1.ValidateTokenRequest{
		Token:          issueResp.AccessToken,
		CheckBlacklist: true,
	}

	validateResp, err := jwtClient.ValidateToken(ctx, validateReq)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}

	if validateResp.Valid {
		fmt.Println("Token is valid")
		if validateResp.Claims != nil {
			fmt.Printf("User ID: %s\n", validateResp.Claims.UserId)
			fmt.Printf("Issued At: %s\n", time.Unix(validateResp.Claims.IssuedAt, 0))
			fmt.Printf("Expires At: %s\n", time.Unix(validateResp.Claims.ExpiresAt, 0))
		}
	} else {
		fmt.Printf("Token is invalid: %s (code: %d)\n", validateResp.Error, validateResp.ErrorCode)
	}

	// Пример 3: Обновление токена
	fmt.Println("\n=== RefreshToken ===")
	refreshReq := &authv1.RefreshTokenRequest{
		RefreshToken: issueResp.RefreshToken,
	}

	refreshResp, err := cl.RefreshToken(ctx, refreshReq)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}

	fmt.Printf("New Access Token: %s\n", refreshResp.AccessToken)
	if refreshResp.RefreshToken != "" {
		fmt.Printf("New Refresh Token: %s\n", refreshResp.RefreshToken)
	}

	// Пример 4: Health Check
	fmt.Println("\n=== HealthCheck ===")
	healthResp, err := cl.HealthCheck(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}

	fmt.Printf("Service is healthy: %v\n", healthResp.Healthy)
	fmt.Printf("Version: %s\n", healthResp.Version)
	fmt.Printf("Uptime: %d seconds\n", healthResp.Uptime)
}
