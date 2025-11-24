module github.com/kabiroman/octawire-auth-service

go 1.24.0

require (
	github.com/octawire/auth-service v0.0.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.10
)

// Для локальной разработки используйте replace:
// Клиент зависит от proto файлов из auth-service
// При использовании в других проектах, убедитесь, что auth-service доступен
replace github.com/octawire/auth-service => ../..

