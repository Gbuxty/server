-- +goose Up
ALTER TABLE users_tokens
ADD COLUMN confirmation_code TEXT,
ADD COLUMN confirmation_code_expires_at TIMESTAMP;

-- +goose Down
ALTER TABLE users_tokens
DROP COLUMN confirmation_code,
DROP COLUMN confirmation_code_expires_at;