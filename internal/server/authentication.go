package server

import (
	"context"
	"fmt"
	"log"
	"server/internal/jwt"
	"server/internal/storage"
	"server/proto/gen"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AuthenticationService struct {
	userStorage  *storage.UserStorage
	jwtSecretKey string
	gen.UnimplementedAuthenticationServer
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

const intervalCleanUp = 24

func NewAuthenticationService(userRepo *storage.UserStorage, jwtSecretKey string, accessTokenTTL time.Duration, refreshTokenTTL time.Duration) *AuthenticationService {
	service := &AuthenticationService{
		userStorage:     userRepo,
		jwtSecretKey:    jwtSecretKey,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
	service.StartTokenCleanUp(intervalCleanUp * time.Hour)
	return service
}

func (s *AuthenticationService) Register(ctx context.Context, req *gen.RegisterRequest) (*gen.RegisterResponse, error) {
	//проверка на совпадения пароля
	/* 	if req.Password != req.Repeatpassword {
	   		return nil, fmt.Errorf("password not match%s", req.Password)
	   	}
	   	//проверка на уникальность емеила
	   	exists, err := s.userStorage.UserExists(ctx, req.Email)
	   	if err != nil {
	   		return nil, fmt.Errorf("failed to check email uniqueness: %w", err)
	   	}

	   	if exists {
	   		return nil, fmt.Errorf("email already exists")
	   	} */

	if err := s.ValidateRegister(ctx, req); err != nil {
		return nil, err
	}
	//хешируем пароль
	password_hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password:%w", err)
	}
	//записываем емеил и хеш пароля в бд
	_, err = s.userStorage.CreateUser(ctx, req.Email, string(password_hash))
	if err != nil {
		return nil, fmt.Errorf("failed to register user: %w", err)
	}

	return &gen.RegisterResponse{Success: true}, nil
}

func (s *AuthenticationService) ValidateRegister(ctx context.Context, req *gen.RegisterRequest) error {
	// Проверка на совпадения пароля
	if req.Password != req.Repeatpassword {
		return fmt.Errorf("password do not match%s", req.Password)
	}
	//проверка на уникальность емеила
	exists, err := s.userStorage.UserExists(ctx, req.Email)
	if err != nil {
		return fmt.Errorf("failed to check email uniqueness: %w", err)
	}

	if exists {
		return fmt.Errorf("email already  exists")
	}
	return nil
}

func (s *AuthenticationService) Login(ctx context.Context, req *gen.LoginRequest) (*gen.LoginResponse, error) {

	log.Println("Starting login process for email:", req.Email)

	user, err := s.userStorage.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	log.Println("User found, checking password")

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	log.Println("Password is valid, generating tokens")
	accessToken, err := jwt.GenerateAccessToken(user.ID, user.Email, s.jwtSecretKey, s.accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, expiresAt, err := jwt.GenerateRefreshToken(s.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	log.Println("Login successful for user:", req.Email)
	if err := s.userStorage.SaveRefreshToken(ctx, user.ID, refreshToken, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}
	log.Println("Login successful for user:", req.Email)
	return &gen.LoginResponse{
		Id:           user.ID,
		Email:        user.Email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthenticationService) Logout(ctx context.Context, req *gen.LogoutRequest) (*gen.LogoutResponse, error) {

	log.Println("Starting logout process for user ID:", req.User.Id)

	// Удаляем Refresh Token пользователя
	if err := s.userStorage.DeleteRefreshToken(ctx, req.User.Id); err != nil {
		log.Printf("Failed to delete refresh token for user ID %d: %v", req.User.Id, err)
		return nil, fmt.Errorf("failed to logout: %w", err)
	}

	log.Println("Logout successful for user ID:", req.User.Id)
	return &gen.LogoutResponse{Success: true}, nil

}

func (s *AuthenticationService) Refresh(ctx context.Context, req *gen.RefreshRequest) (*gen.RefreshResponse, error) {
	log.Println("Starting refresh process")

	//  Получаем userID по refreshToken
	userID, expiresAt, err := s.userStorage.GetUserIDByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Printf("Invalid or expired refresh token: %v", err)
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	// Проверяем  срок действия RefreshToken
	if time.Now().After(expiresAt) {
		if err := s.userStorage.DeleteRefreshToken(ctx, userID); err != nil {
			log.Printf("Failed to delete expired refresh token for user ID %d: %v", userID, err)
		}
		return nil, fmt.Errorf("refresh token expired")
	}
	//  Получаем данные пользователя по userID
	user, err := s.userStorage.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("Failed to get user by ID %d: %v", userID, err)
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	//  Генерируем новые токены
	accessToken, err := jwt.GenerateAccessToken(user.ID, user.Email, s.jwtSecretKey, s.accessTokenTTL)
	if err != nil {
		log.Printf("Failed to generate access token for user %s: %v", user.Email, err)
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	refreshToken, expiresAt, err := jwt.GenerateRefreshToken(s.refreshTokenTTL)
	if err != nil {
		log.Printf("Failed to generate refresh token for user %s: %v", user.Email, err)
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	//  Сохраняем новый refreshToken в базе данных
	if err := s.userStorage.SaveRefreshToken(ctx, user.ID, refreshToken, expiresAt); err != nil {
		log.Printf("Failed to save refresh token for user %s: %v", user.Email, err)
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	log.Println("Tokens refreshed successfully for user ID:", user.ID)
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
	log.Println("Starting Me process")

	// Извлекаем user_id из access token
	userID, err := jwt.ExtractUserIDFromToken(req.AccessToken, s.jwtSecretKey)
	if err != nil {
		log.Printf("Failed to extract user ID from token: %v", err)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Получаем данные пользователя по user_id
	user, err := s.userStorage.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("Failed to get user by ID %d: %v", userID, err)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	log.Println("User info retrieved successfully for user ID:", user.ID)
	return &gen.MeResponse{
		Id:    user.ID,
		Email: user.Email,
	}, nil

}

func (s *AuthenticationService) StartTokenCleanUp(interval time.Duration) {
	go func() {

		for {

			time.Sleep(interval)
			log.Println("Starting token cleanup...")

			if err := s.userStorage.DeleteExpiredRefreshTokens(context.Background()); err != nil {
				log.Printf("Failed to delete expired refresh tokens: %v", err)
			}
			log.Println("Token cleanup completed")
		}
	}()

}
