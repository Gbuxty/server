package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"time"

	"github.com/golang-jwt/jwt"
)


func GenerateAccessToken(userID int64,email string,secretKey string,accessTokenTTL time.Duration)(string,error){

	claims:=jwt.MapClaims{
		"user_id":userID,
		"email":email,
		"exp":time.Now().Add(accessTokenTTL).Unix(),
	}
	token:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	return token.SignedString([]byte(secretKey))
}

func GenerateRefreshToken(refreshTokenTTL time.Duration) (string, time.Time, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	token := hex.EncodeToString(bytes)
	expiresAt := time.Now().Add(refreshTokenTTL)
	return token, expiresAt, nil
}

func ExtractUserIDFromToken(tokenString string,secretKey string)(int64,error){
	if tokenString == "" {
		return 0, fmt.Errorf("token is empty")
	}
	segments := strings.Split(tokenString, ".")
	if len(segments) != 3 {
		return 0, fmt.Errorf("token contains an invalid number of segments")
	}
	log.Printf("Token to parse: %s", tokenString) // Логируем токен
// Парсим токен
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	// Проверяем метод подписи
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(secretKey), nil
})
if err != nil {
	return 0, fmt.Errorf("failed to parse token: %w", err)
}

// Проверяем, валиден ли токен
if !token.Valid {
	return 0, fmt.Errorf("invalid token")
}

// Извлекаем claims (полезную нагрузку)
claims, ok := token.Claims.(jwt.MapClaims)
if !ok {
	return 0, fmt.Errorf("failed to extract claims from token")
}

// Извлекаем user_id
userID, ok := claims["user_id"].(float64) // JWT числа всегда float64
if !ok {
	return 0, fmt.Errorf("user_id not found in token claims")
}

return int64(userID), nil	
}