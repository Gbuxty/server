package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"server/internal/config"
	"server/internal/database"
	"server/internal/server"
	"server/internal/storage"
	"server/proto/gen"
	"syscall"

	"google.golang.org/grpc"
)

func main() {
	//конфиги
	cfg, err := config.LoadConfig("config/local.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	// подключение к бд
	db, err := database.NewDB(cfg.StoragePath)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	//	инициалзация репозиториев и сервиса
	userRepo := storage.NewUserStorage(db)
	authService := server.NewAuthenticationService(userRepo, cfg.JWT.SecretKey, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	//запуск севера
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Run(ctx, cfg.Grpc.Port, authService)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Server stopped")
}

func Run(ctx context.Context, port string, authService *server.AuthenticationService) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	gen.RegisterAuthenticationServer(grpcServer, authService)

	go func() {
		log.Printf("Server is running on port %s", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-ctx.Done()

	log.Println("Stopping gRPC server...")
	grpcServer.GracefulStop()
	
}
