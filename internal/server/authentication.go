package server

import (
	"context"
	"fmt"
	"server/internal/config"
	"server/internal/jwt"
	"server/internal/logger"
	"server/internal/storage"
	"server/proto/gen"
	"time"

	"github.com/mailgun/mailgun-go"
	"go.uber.org/zap"

	"golang.org/x/crypto/bcrypt"
)

type AuthenticationService struct {
	userStorage  *storage.UserStorage
	jwtSecretKey string
	logger       *logger.Logger
	gen.UnimplementedAuthenticationServer
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	mailgunConfig   *config.MailgunConfig
}

func NewAuthenticationService(userRepo *storage.UserStorage, jwtSecretKey string, accessTokenTTL time.Duration, refreshTokenTTL time.Duration, log *logger.Logger, mailgunConfig *config.MailgunConfig) *AuthenticationService {
	service := &AuthenticationService{
		userStorage:     userRepo,
		jwtSecretKey:    jwtSecretKey,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		logger:          log,
		mailgunConfig:   mailgunConfig,
	}

	return service
}

func (s *AuthenticationService) Register(ctx context.Context, req *gen.RegisterRequest) (*gen.RegisterResponse, error) {

	s.logger.Logger.Info("Registering new user", zap.String("email", req.Email))

	if err := s.ValidateRegister(ctx, req); err != nil {
		s.logger.Logger.Error("Validation failed", zap.String("email", req.Email), zap.Error(err))
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Logger.Error("Failed to hash password", zap.String("email", req.Email), zap.Error(err))
		return nil, fmt.Errorf("failed to hash password:%w", err)
	}

	userID, err := s.userStorage.CreateUser(ctx, req.Email, string(passwordHash))
	if err != nil {
		s.logger.Logger.Error("Failed to create user", zap.String("email", req.Email), zap.Error(err))
		return nil, fmt.Errorf("failed to register user: %w", err)
	}

	confirmationToken, expiresAt, err := jwt.GenerateConfirmationToken(userID, s.jwtSecretKey, 24*time.Hour, s.logger)
	if err != nil {
		s.logger.Logger.Error("Failed to generate confirmation token", zap.Error(err))
		return nil, fmt.Errorf("failed to generate confirmation token: %w", err)
	}

	// Сохранение токена в базе данных
	if err := s.userStorage.SaveConfirmationToken(ctx, userID, confirmationToken, expiresAt); err != nil {
		s.logger.Logger.Error("Failed to save confirmation token", zap.Error(err))
		return nil, fmt.Errorf("failed to save confirmation token: %w", err)
	}

	// Отправка письма через Mailgun
	mg := mailgun.NewMailgun(s.mailgunConfig.Domain, s.mailgunConfig.ApiKey)
	message := mg.NewMessage(
		s.mailgunConfig.FromEmail,
		"Confirm your email",
		"Please confirm your email by clicking the link: http://mygeorgedomen.com/confirm?token="+confirmationToken,
		req.Email,
	)
	_, _, err = mg.Send(message)
	if err != nil {
		s.logger.Logger.Error("Failed to send confirmation email", zap.Error(err))
		return nil, fmt.Errorf("failed to send confirmation email: %w", err)
	}
	s.logger.Logger.Info("User registered successfully", zap.String("email", req.Email))

	return &gen.RegisterResponse{Success: true}, nil
}

func (s *AuthenticationService) ValidateRegister(ctx context.Context, req *gen.RegisterRequest) error {
	s.logger.Logger.Info("Validating registration request", zap.String("email", req.Email))

	if req.Password != req.RepeatPassword {
		s.logger.Logger.Error("Passwords do not match", zap.String("email", req.Email))
		return fmt.Errorf("Password do not match%s", req.Password)
	}

	exists, err := s.userStorage.UserExists(ctx, req.Email)
	if err != nil {
		s.logger.Logger.Error("Failed to check email uniqueness", zap.String("email", req.Email), zap.Error(err))
		return fmt.Errorf("failed to check email uniqueness: %w", err)
	}

	if exists {
		s.logger.Logger.Error("Email already exists", zap.String("email", req.Email))
		return fmt.Errorf("email already  exists")
	}
	s.logger.Logger.Info("Registration validation successful", zap.String("email", req.Email))
	return nil
}

func (s *AuthenticationService) Login(ctx context.Context, req *gen.LoginRequest) (*gen.LoginResponse, error) {
	s.logger.Logger.Info("Logging in user", zap.String("email", req.Email))

	user, err := s.userStorage.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Logger.Error("Failed to fetch user by email", zap.String("email", req.Email), zap.Error(err))
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.logger.Logger.Error("Invalid password", zap.String("email", req.Email))
		return nil, fmt.Errorf("invalid password")
	}

	accessToken, accessTokenExpiresAt, err := jwt.GenerateAccessToken(user.ID, user.Email, s.jwtSecretKey, s.accessTokenTTL, s.logger)
	if err != nil {
		s.logger.Logger.Error("Failed to generate access token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshTokenExpiresAt, err := jwt.GenerateRefreshToken(user.ID, user.Email, s.jwtSecretKey, s.refreshTokenTTL, s.logger)
	if err != nil {
		s.logger.Logger.Error("Failed to generate refresh token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := s.userStorage.SaveRefreshToken(ctx, user.ID, refreshToken, refreshTokenExpiresAt); err != nil {
		s.logger.Logger.Error("Failed to save refresh token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	if err := s.userStorage.SaveAccessToken(ctx, user.ID, accessToken, accessTokenExpiresAt); err != nil {
		s.logger.Logger.Error("Failed to save access token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	s.logger.Logger.Info("User logged in successfully", zap.Int64("userID", user.ID), zap.String("email", user.Email))
	return &gen.LoginResponse{
		User: &gen.User{
			Id:    user.ID,
			Email: user.Email,
		},
		AccessToken: &gen.AccessToken{
			Token:     accessToken,
			ExpiresAt: time.Now().Add(s.accessTokenTTL).Unix(),
		},
		RefreshToken: &gen.RefreshToken{
			Token:     refreshToken,
			ExpiresAt: time.Now().Add(s.refreshTokenTTL).Unix(),
		},
	}, nil
}

func (s *AuthenticationService) Logout(ctx context.Context, req *gen.LogoutRequest) (*gen.LogoutResponse, error) {

	s.logger.Logger.Info("Logging out user", zap.Int64("userID", req.User.Id))

	// Удаляем Refresh Token пользователя
	if err := s.userStorage.DeleteRefreshToken(ctx, req.User.Id); err != nil {
		s.logger.Logger.Error("Failed to delete refresh token", zap.Int64("userID", req.User.Id), zap.Error(err))
		return nil, fmt.Errorf("failed to logout: %w", err)
	}

	if err := s.userStorage.DeleteAccesshToken(ctx, req.User.Id); err != nil {
		s.logger.Logger.Error("Failed to delete access token", zap.Int64("userID", req.User.Id), zap.Error(err))
		return nil, fmt.Errorf("failed to logout: %w", err)
	}
	s.logger.Logger.Info("User logged out successfully", zap.Int64("userID", req.User.Id))
	return &gen.LogoutResponse{Success: true}, nil

}

func (s *AuthenticationService) Refresh(ctx context.Context, req *gen.RefreshRequest) (*gen.RefreshResponse, error) {
	s.logger.Logger.Info("Refreshing tokens", zap.String("refreshToken", req.RefreshToken))

	//  Получаем userID по refreshToken
	userID, expiresAt, err := s.userStorage.GetUserIDByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		s.logger.Logger.Error("Invalid refresh token", zap.String("refreshToken", req.RefreshToken), zap.Error(err))
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	// Проверяем  срок действия RefreshToken
	if time.Now().After(expiresAt) {
		s.logger.Logger.Error("Refresh token expired", zap.Int64("userID", userID))
		if err := s.userStorage.DeleteRefreshToken(ctx, userID); err != nil {
			s.logger.Logger.Error("Failed to delete expired refresh token", zap.Int64("userID", userID), zap.Error(err))
		}
		return nil, fmt.Errorf("refresh token expired")
	}
	//  Получаем данные пользователя по userID
	user, err := s.userStorage.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Logger.Error("Failed to fetch user by ID", zap.Int64("userID", userID), zap.Error(err))
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	//  Генерируем новые токены
	accessToken, accessTokenExpiresAt, err := jwt.GenerateAccessToken(user.ID, user.Email, s.jwtSecretKey, s.accessTokenTTL, s.logger)
	if err != nil {
		s.logger.Logger.Error("Failed to generate access token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshTokenExpiresAt, err := jwt.GenerateRefreshToken(user.ID, user.Email, s.jwtSecretKey, s.refreshTokenTTL, s.logger)
	if err != nil {
		s.logger.Logger.Error("Failed to generate refresh token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	//  Сохраняем новый refreshToken в базе данных
	if err := s.userStorage.SaveAccessToken(ctx, user.ID, accessToken, accessTokenExpiresAt); err != nil {
		s.logger.Logger.Error("Failed to save access token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	if err := s.userStorage.SaveRefreshToken(ctx, user.ID, refreshToken, refreshTokenExpiresAt); err != nil {
		s.logger.Logger.Error("Failed to save refresh token", zap.Int64("userID", user.ID), zap.Error(err))
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	s.logger.Logger.Info("Tokens refreshed successfully", zap.Int64("userID", user.ID))
	return &gen.RefreshResponse{
		AccessToken: &gen.AccessToken{
			Token:     accessToken,
			ExpiresAt: time.Now().Add(s.accessTokenTTL).Unix(),
		},
		RefreshToken: &gen.RefreshToken{
			Token:     refreshToken,
			ExpiresAt: expiresAt.Unix(),
		},
	}, nil
}

func (s *AuthenticationService) Me(ctx context.Context, req *gen.MeRequest) (*gen.MeResponse, error) {

	s.logger.Logger.Info("Fetching user info", zap.String("accessToken", req.AccessToken))
	// Извлекаем user_id из access token
	userID, err := jwt.ExtractUserIDFromToken(req.AccessToken, s.jwtSecretKey, s.logger)
	if err != nil {
		s.logger.Logger.Error("Failed to extract user ID from token", zap.String("accessToken", req.AccessToken), zap.Error(err))
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Получаем данные пользователя по user_id
	user, err := s.userStorage.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Logger.Error("Failed to fetch user by ID", zap.Int64("userID", userID), zap.Error(err))
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	s.logger.Logger.Info("User info fetched successfully", zap.Int64("userID", user.ID), zap.String("email", user.Email))
	return &gen.MeResponse{
		User: &gen.User{
			Id:    user.ID,
			Email: user.Email},
	}, nil

}

func (s *AuthenticationService) ConfirmEmail(ctx context.Context, req *gen.ConfirmEmailRequest) (*gen.ConfirmEmailResponse, error) {
	s.logger.Logger.Info("Confirming email", zap.String("confirmation_token", req.ConfirmationToken))

	// Проверяем токен и подтверждаем email
	userID, err := s.userStorage.ConfirmEmail(ctx, req.ConfirmationToken)
	if err != nil {
		s.logger.Logger.Error("Failed to confirm email", zap.Error(err))
		return nil, fmt.Errorf("failed to confirm email: %w", err)
	}

	s.logger.Logger.Info("Email confirmed successfully", zap.Int64("userID", userID))
	return &gen.ConfirmEmailResponse{Success: true}, nil
}
