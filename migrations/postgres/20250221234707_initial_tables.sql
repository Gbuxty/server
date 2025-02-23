-- +goose Up
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_confirmed BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    access_token VARCHAR(255),
    refresh_token VARCHAR(255),
    refresh_token_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    access_token_expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    confirmation_token VARCHAR(255),
    confirmation_token_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- +goose Down
DROP TABLE users_tokens;
DROP TABLE users;