-- +goose Up
ALTER TABLE users_tokens
DROP COLUMN confirmation_token_expires_at,
DROP COLUMN confirmation_token;

-- +goose Down
ALTER TABLE users_tokens
ADD COLUMN confirmation_token TEXT,
ADD COLUMN confirmation_token_expires_at TIMESTAMP;