package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"server/internal/config"
	"server/internal/database"
	"server/internal/logger"
	"server/internal/server"
	"server/internal/storage"
	"server/proto/gen"
	"syscall"

	"google.golang.org/grpc"
	"go.uber.org/zap"
)

func main() {
	// Инициализация логгера
	log, err := logger.New()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	defer log.Sync()

	log.Logger.Info("Starting server...")

	// Загрузка конфигурации
	cfg, err := config.LoadConfig("config/local.yaml")
	if err != nil {
		log.Logger.Error("Failed to load config", zap.Error(err))
		panic(err)
	}

	// Подключение к базе данных
	db, err := database.NewDB(cfg.StoragePath)
	if err != nil {
		log.Logger.Error("Failed to connect to DB", zap.Error(err))
		panic(err)
	}
	defer db.CloseDb()

	log.Logger.Info("Connected to database")

	// Инициализация репозиториев и сервиса
	userRepo := storage.NewUserStorage(db.Conn, log)
	authService := server.NewAuthenticationService(userRepo, cfg.JWT.SecretKey, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, log,cfg.Mailgun)

	// Запуск сервера
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Run(ctx, cfg.Grpc.Port, authService, log)

	// Ожидание сигнала завершения
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Logger.Info("Shutting down server...")
	cancel() // Отмена контекста для завершения работы сервера
}

func Run(ctx context.Context, port string, authService *server.AuthenticationService, log *logger.Logger) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Logger.Error("Failed to listen TCP", zap.Error(err))
		return
	}

	grpcServer := grpc.NewServer()
	gen.RegisterAuthenticationServer(grpcServer, authService)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Logger.Error("Failed to serve gRPC", zap.Error(err))
		}
	}()

	<-ctx.Done()
	grpcServer.GracefulStop()
}