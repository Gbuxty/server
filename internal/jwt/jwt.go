package jwt

import (
	"fmt"
	"server/internal/logger"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
)

func GenerateAccessToken(userID int64, email string, secretKey string, accessTokenTTL time.Duration, log *logger.Logger) (string, time.Time, error) {
	log.Logger.Info("Generating access token", zap.Int64("userID", userID), zap.String("email", email))

	expiresAt := time.Now().Add(accessTokenTTL)

	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(accessTokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		log.Logger.Error("Failed to generate access token", zap.Int64("userID", userID), zap.Error(err))
		return "", time.Time{}, fmt.Errorf("failed to generate access token: %w", err)
	}
	log.Logger.Info("Access token generated successfully", zap.Int64("userID", userID), zap.String("email", email))
	return signedToken, expiresAt, nil
}

func GenerateRefreshToken(userID int64, email string, secretKey string, refreshTokenTTL time.Duration, log *logger.Logger) (string, time.Time, error) {
	log.Logger.Info("Generating refresh token", zap.Int64("userID", userID), zap.String("email", email))

	expiresAt := time.Now().Add(refreshTokenTTL)

	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(refreshTokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		log.Logger.Error("Failed to generate refresh token", zap.Int64("userID", userID), zap.Error(err))
		return "", time.Time{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	log.Logger.Info("Refresh token expires at", zap.Time("expiresAt", expiresAt))
	log.Logger.Info("Refresh token generated successfully", zap.Int64("userID", userID), zap.String("email", email))
	return signedToken, expiresAt, nil
}



func ExtractUserIDFromToken(tokenString string, secretKey string, log *logger.Logger) (int64, error) {
	log.Logger.Info("Extracting user ID from token")

	if tokenString == "" {
		log.Logger.Error("Token is empty")
		return 0, fmt.Errorf("token is empty")
	}
	segments := strings.Split(tokenString, ".")
	if len(segments) != 3 {
		log.Logger.Error("Invalid token segments", zap.Int("segments", len(segments)))
		return 0, fmt.Errorf("token contains an invalid number of segments")
	}

	// Парсим токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Logger.Error("Unexpected signing method", zap.String("alg", token.Header["alg"].(string)))
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Logger.Error("Failed to parse token", zap.Error(err))
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}

	// Проверяем, валиден ли токен
	if !token.Valid {
		log.Logger.Error("Invalid token")
		return 0, fmt.Errorf("invalid token")
	}

	// Извлекаем claims (полезную нагрузку)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Logger.Error("Failed to extract claims from token")
		return 0, fmt.Errorf("failed to extract claims from token")
	}

	// Извлекаем user_id
	userID, ok := claims["user_id"].(float64) // JWT числа всегда float64
	if !ok {
		log.Logger.Error("UserID not found in token claims")
		return 0, fmt.Errorf("user_id not found in token claims")
	}

	log.Logger.Info("UserID extracted from token", zap.Int64("userID", int64(userID)))
	return int64(userID), nil
}
