package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type UserStorage struct {
	db *pgxpool.Pool
}
type User struct {
	ID           int64
	Email        string
	PasswordHash string
}

func NewUserStorage(db *pgxpool.Pool) *UserStorage {
	return &UserStorage{db: db}
}

func (r *UserStorage) CreateUser(ctx context.Context, email, password string) (int64, error) {

	var id int64

	query := `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`
	err := r.db.QueryRow(ctx, query, email, password).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to creat user %w", err)
	}

	return id, nil

}

func (r *UserStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	query := `SELECT id, email, password_hash FROM users WHERE email = $1`
	err := r.db.QueryRow(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get user BY email: %w", err)
	}
	return &user, nil
}

func (r *UserStorage) GetUserByID(ctx context.Context, userID int64) (*User, error) {
	var user User
	query := `SELECT id, email, password_hash FROM users WHERE id = $1`
	err := r.db.QueryRow(ctx, query, userID).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user with ID %d not found", userID)
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	return &user, nil
}
func (r *UserStorage) GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (int64, time.Time, error) {
	var userID int64
	var expiresAt time.Time
	query := `SELECT id,refresh_token_expires_at  FROM users WHERE refresh_token = $1`
	err := r.db.QueryRow(ctx, query, refreshToken).Scan(&userID, &expiresAt)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to get userid BY refresh token: %w", err)
	}
	if time.Now().After(expiresAt) {
		return 0, time.Time{}, fmt.Errorf("refresh token expired")
	}
	return userID, expiresAt, nil
}

func (r *UserStorage) UserExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	err := r.db.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user%w", err)
	}
	return exists, nil
}

func (r *UserStorage) SaveRefreshToken(ctx context.Context, userID int64, refreshToken string, expiresAt time.Time) error {
	query := `UPDATE users SET refresh_token = $1,refresh_token_expires_at = $2 WHERE id = $3`
	_, err := r.db.Exec(ctx, query, refreshToken, expiresAt, userID)
	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}
	return nil
}

func (r *UserStorage) DeleteRefreshToken(ctx context.Context, userID int64) error {
	query := `UPDATE users SET refresh_token = NULL, refresh_token_expires_at = NULL WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		log.Printf("Failed to delete refresh token for user ID %d: %v", userID, err)
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	log.Println("Refresh token deleted successfully for user ID:", userID)
	return nil
}

func (r *UserStorage) DeleteExpiredRefreshTokens(ctx context.Context) error {
	query := `UPDATE users SET refresh_token = NULL, refresh_token_expires_at = NULL WHERE refresh_token_expires_at < NOW()`
	_, err := r.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}
	return nil
}
