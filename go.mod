module github.com/octawire/auth-service/clients/go

go 1.24.0

require (
	github.com/octawire/auth-service v0.0.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.10
)

replace github.com/octawire/auth-service => ../..

