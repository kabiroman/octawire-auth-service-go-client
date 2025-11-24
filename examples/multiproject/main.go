package main

import (
	"context"
	"fmt"
	"log"

	"github.com/kabiroman/octawire-auth-service-go-client"
	authv1 "github.com/octawire/auth-service/internal/proto"
)

func main() {
	// Создаем конфигурацию клиента
	config := client.DefaultConfig("localhost:50051")
	// Не устанавливаем дефолтный ProjectID, будем указывать в каждом запросе

	// Создаем клиент
	cl, err := client.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer cl.Close()

	ctx := context.Background()

	// Пример 1: Работа с проектом A
	fmt.Println("=== Project A ===")
	projectA := "project-a-uuid"

	issueReqA := &authv1.IssueTokenRequest{
		UserId:    "user-123",
		ProjectId: projectA,
	}

	issueRespA, err := cl.IssueToken(ctx, issueReqA)
	if err != nil {
		log.Fatalf("Failed to issue token for project A: %v", err)
	}

	fmt.Printf("Project A - Access Token: %s\n", issueRespA.AccessToken)
	fmt.Printf("Project A - Key ID: %s\n", issueRespA.KeyId)

	// Получаем публичный ключ для проекта A
	keyReqA := &authv1.GetPublicKeyRequest{
		ProjectId: projectA,
	}

	keyRespA, err := cl.GetPublicKey(ctx, keyReqA)
	if err != nil {
		log.Fatalf("Failed to get public key for project A: %v", err)
	}

	fmt.Printf("Project A - Public Key Algorithm: %s\n", keyRespA.Algorithm)
	fmt.Printf("Project A - Key ID: %s\n", keyRespA.KeyId)

	// Пример 2: Работа с проектом B
	fmt.Println("\n=== Project B ===")
	projectB := "project-b-uuid"

	issueReqB := &authv1.IssueTokenRequest{
		UserId:    "user-456",
		ProjectId: projectB,
	}

	issueRespB, err := cl.IssueToken(ctx, issueReqB)
	if err != nil {
		log.Fatalf("Failed to issue token for project B: %v", err)
	}

	fmt.Printf("Project B - Access Token: %s\n", issueRespB.AccessToken)
	fmt.Printf("Project B - Key ID: %s\n", issueRespB.KeyId)

	// Получаем публичный ключ для проекта B
	keyReqB := &authv1.GetPublicKeyRequest{
		ProjectId: projectB,
	}

	keyRespB, err := cl.GetPublicKey(ctx, keyReqB)
	if err != nil {
		log.Fatalf("Failed to get public key for project B: %v", err)
	}

	fmt.Printf("Project B - Public Key Algorithm: %s\n", keyRespB.Algorithm)
	fmt.Printf("Project B - Key ID: %s\n", keyRespB.KeyId)

	// Пример 3: Работа с API ключами для разных проектов
	fmt.Println("\n=== API Keys for Project A ===")

	createAPIKeyReqA := &authv1.CreateAPIKeyRequest{
		ProjectId: projectA,
		UserId:    "user-123",
		Name:      "Project A API Key",
		Scopes:    []string{"read", "write"},
		Ttl:       86400 * 30, // 30 дней
	}

	createAPIKeyRespA, err := cl.CreateAPIKey(ctx, createAPIKeyReqA)
	if err != nil {
		log.Fatalf("Failed to create API key for project A: %v", err)
	}

	fmt.Printf("Project A - API Key ID: %s\n", createAPIKeyRespA.KeyId)
	fmt.Printf("Project A - API Key: %s\n", createAPIKeyRespA.ApiKey)

	// Список API ключей для проекта A
	listAPIKeysReqA := &authv1.ListAPIKeysRequest{
		ProjectId: projectA,
		Page:      1,
		PageSize:  10,
	}

	listAPIKeysRespA, err := cl.ListAPIKeys(ctx, listAPIKeysReqA)
	if err != nil {
		log.Fatalf("Failed to list API keys for project A: %v", err)
	}

	fmt.Printf("Project A - Total API Keys: %d\n", listAPIKeysRespA.Total)
	for i, key := range listAPIKeysRespA.Keys {
		fmt.Printf("  [%d] Key ID: %s, Name: %s, Active: %v\n",
			i+1, key.KeyId, key.Name, key.Active)
	}

	// Пример 4: Использование дефолтного проекта из конфигурации
	fmt.Println("\n=== Default Project ===")
	configWithDefault := client.DefaultConfig("localhost:50051")
	configWithDefault.ProjectID = "default-project-id"

	clWithDefault, err := client.NewClient(configWithDefault)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer clWithDefault.Close()

	// Не указываем ProjectId в запросе, будет использован из конфигурации
	issueReqDefault := &authv1.IssueTokenRequest{
		UserId: "user-789",
		// ProjectId не указан, будет использован configWithDefault.ProjectID
	}

	issueRespDefault, err := clWithDefault.IssueToken(ctx, issueReqDefault)
	if err != nil {
		log.Fatalf("Failed to issue token for default project: %v", err)
	}

	fmt.Printf("Default Project - Access Token: %s\n", issueRespDefault.AccessToken)
	fmt.Printf("Default Project - Key ID: %s\n", issueRespDefault.KeyId)
}

