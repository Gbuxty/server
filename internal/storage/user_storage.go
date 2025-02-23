package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"server/internal/logger"
	"time"

	"go.uber.org/zap"

	"github.com/jackc/pgx/v5/pgxpool"
)

type UserStorage struct {
	db     *pgxpool.Pool
	logger *logger.Logger
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
}

func NewUserStorage(db *pgxpool.Pool, log *logger.Logger) *UserStorage {
	return &UserStorage{
		db:     db,
		logger: log,
	}
}

func (r *UserStorage) CreateUser(ctx context.Context, email, password string) (int64, error) {
	var id int64

	r.logger.Logger.Info("Create User", zap.String("email", email))

	query := `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`
	err := r.db.QueryRow(ctx, query, email, password).Scan(&id)
	if err != nil {
		r.logger.Logger.Error("Failed to create user", zap.String("email", email), zap.Error(err))
		return 0, fmt.Errorf("failed to creat user %w", err)
	}
	r.logger.Logger.Info("User created successfully", zap.Int64("id", id), zap.String("email", email))
	return id, nil

}

func (r *UserStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User

	r.logger.Logger.Info("Fetching user by email", zap.String("email", email))

	query := `SELECT id, email, password_hash FROM users WHERE email = $1`
	err := r.db.QueryRow(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		r.logger.Logger.Error("Failed to fetch user by email", zap.String("email", email), zap.Error(err))
		return nil, fmt.Errorf("failed to get user BY email: %w", err)
	}

	r.logger.Logger.Info("User fetched successfully", zap.Int64("id", user.ID), zap.String("email", user.Email))

	return &user, nil
}

func (r *UserStorage) GetUserByID(ctx context.Context, userID int64) (*User, error) {
	var user User

	r.logger.Logger.Info("Fetching user by ID", zap.Int64("userID", userID))

	query := `SELECT id, email, password_hash FROM users WHERE id = $1`
	err := r.db.QueryRow(ctx, query, userID).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			r.logger.Logger.Error("User not found", zap.Int64("userID", userID))
			return nil, fmt.Errorf("user with ID %d not found", userID)
		}
		r.logger.Logger.Error("Failed to fetch user by ID", zap.Int64("userID", userID), zap.Error(err))
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	r.logger.Logger.Info("User fetched successfully", zap.Int64("id", user.ID), zap.String("email", user.Email))
	return &user, nil
}
func (r *UserStorage) GetUserIDByRefreshToken(ctx context.Context, refreshToken string) (int64, time.Time, error) {
	var (
		userID    int64
		expiresAt time.Time
	)

	r.logger.Logger.Info("Fetching user ID by refresh token")

	query := `SELECT user_id,refresh_token_expires_at  FROM users_tokens WHERE refresh_token = $1`
	err := r.db.QueryRow(ctx, query, refreshToken).Scan(&userID, &expiresAt)
	if err != nil {
		r.logger.Logger.Error("Failed to fetch user ID by refresh token", zap.Error(err))
		return 0, time.Time{}, fmt.Errorf("failed to get userid BY refresh token: %w", err)
	}
	if time.Now().After(expiresAt) {
		r.logger.Logger.Error("Refresh token expired", zap.Int64("userID", userID))
		return 0, time.Time{}, fmt.Errorf("refresh token expired")
	}
	r.logger.Logger.Info("User ID fetched successfully", zap.Int64("userID", userID))
	return userID, expiresAt, nil
}

func (r *UserStorage) UserExists(ctx context.Context, email string) (bool, error) {
	var exists bool

	r.logger.Logger.Info("Checking if user exists", zap.String("email", email))

	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	err := r.db.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		r.logger.Logger.Error("Failed to check if user exists", zap.String("email", email), zap.Error(err))
		return false, fmt.Errorf("failed to check user%w", err)
	}

	r.logger.Logger.Info("User existence check completed", zap.String("email", email), zap.Bool("exists", exists))

	return exists, nil
}

func (r *UserStorage) SaveRefreshToken(ctx context.Context, userID int64, refreshToken string, expiresAt time.Time) error {
	r.logger.Logger.Info("Saving refresh token", zap.Int64("userID", userID))

	query := `INSERT INTO users_tokens (user_id, refresh_token, refresh_token_expires_at) 
	          VALUES ($1, $2, $3) 
	          ON CONFLICT (user_id) 
	          DO UPDATE SET refresh_token = $2, refresh_token_expires_at = $3`
	_, err := r.db.Exec(ctx, query, userID, refreshToken, expiresAt)
	if err != nil {
		r.logger.Logger.Error("Failed to save refresh token", zap.Int64("userID", userID), zap.Error(err))
		return fmt.Errorf("failed to save refresh token: %w", err)
	}
	r.logger.Logger.Info("Refresh token saved successfully", zap.Int64("userID", userID))
	return nil
}

func (r *UserStorage) SaveAccessToken(ctx context.Context, userID int64, accessToken string, expiresAt time.Time) error {
	r.logger.Logger.Info("Saving access token", zap.Int64("userID", userID))

	query := `INSERT INTO users_tokens (user_id, access_token, access_token_expires_at) 
	          VALUES ($1, $2, $3) 
	          ON CONFLICT (user_id) 
	          DO UPDATE SET access_token = $2, access_token_expires_at = $3`
	_, err := r.db.Exec(ctx, query, userID, accessToken, expiresAt)
	if err != nil {
		r.logger.Logger.Error("Failed to save access token", zap.Int64("userID", userID), zap.Error(err))
		return fmt.Errorf("failed to save access token: %w", err)
	}
	r.logger.Logger.Info("Access token saved successfully", zap.Int64("userID", userID))
	return nil
}

func (r *UserStorage) DeleteRefreshToken(ctx context.Context, userID int64) error {
	r.logger.Logger.Info("Deleting refresh token", zap.Int64("userID", userID))

	query := `UPDATE users_tokens SET refresh_token = NULL, refresh_token_expires_at = NULL WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Logger.Error("Failed to delete refresh token", zap.Int64("userID", userID), zap.Error(err))
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	r.logger.Logger.Info("Refresh token deleted successfully", zap.Int64("userID", userID))
	return nil
}

func (r *UserStorage) DeleteAccesshToken(ctx context.Context, userID int64) error {
	r.logger.Logger.Info("Deleting access token", zap.Int64("userID", userID))

	query := `UPDATE users_tokens SET access_token = NULL, access_token_expires_at = NULL WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Logger.Error("Failed to delete access token", zap.Int64("userID", userID), zap.Error(err))
		return fmt.Errorf("failed to delete access token: %w", err)
	}
	r.logger.Logger.Info("Access token deleted successfully", zap.Int64("userID", userID))
	return nil
}
func (r *UserStorage) DeleteExpiredRefreshTokens(ctx context.Context) error { // а на хуй оно надо?
	r.logger.Logger.Info("Deleting expired refresh tokens")

	query := `UPDATE users SET refresh_token = NULL, refresh_token_expires_at = NULL WHERE refresh_token_expires_at < NOW()`
	_, err := r.db.Exec(ctx, query)
	if err != nil {
		r.logger.Logger.Error("Failed to delete expired refresh tokens", zap.Error(err))
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}
	r.logger.Logger.Info("Expired refresh tokens deleted successfully")
	return nil
}
func (r *UserStorage) ConfirmEmail(ctx context.Context, confirmationToken string) (int64, error) {
    r.logger.Logger.Info("Confirming email", zap.String("confirmation_token", confirmationToken))

    var userID int64
    query := `  UPDATE users
        SET email_confirmed = true
        WHERE id = (
            SELECT user_id
            FROM users_tokens
            WHERE confirmation_token = $1
        )
        RETURNING id`
    err := r.db.QueryRow(ctx, query, confirmationToken).Scan(&userID)
    if err != nil {
        r.logger.Logger.Error("Failed to confirm email", zap.Error(err))
        return 0, fmt.Errorf("failed to confirm email: %w", err)
    }

    r.logger.Logger.Info("Email confirmed successfully", zap.Int64("userID", userID))
    return userID, nil
}

func (r *UserStorage) SaveConfirmationToken(ctx context.Context, userID int64, token string, expiresAt time.Time) error {
	r.logger.Logger.Info("Saving confirmation token", zap.Int64("userID", userID))

	query := `
		INSERT INTO users_tokens (user_id, confirmation_token, confirmation_token_expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id)
		DO UPDATE SET confirmation_token = $2, confirmation_token_expires_at = $3
	`
	_, err := r.db.Exec(ctx, query, userID, token, expiresAt)
	if err != nil {
		r.logger.Logger.Error("Failed to save confirmation token", zap.Error(err))
		return fmt.Errorf("failed to save confirmation token: %w", err)
	}

	r.logger.Logger.Info("Confirmation token saved successfully", zap.Int64("userID", userID))
	return nil
}