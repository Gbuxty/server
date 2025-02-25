-- +goose Up
-- +goose StatementBegin
-- Удаляем токены пользователя
DELETE FROM users_tokens WHERE user_id = (SELECT id FROM users WHERE email = '1kartofan@gmail.com');

-- Удаляем пользователя
DELETE FROM users WHERE email = '1kartofan@gmail.com';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Восстанавливаем пользователя
INSERT INTO users (email, password_hash, email_confirmed)
VALUES ('1kartofan@gmail.com', '$2a$10$OE76CRIy8rV1EHmDZyAt3.xB2HxvtZiQcQS0ILhoCT.CXa4xeua06', false);

-- Восстанавливаем токены
INSERT INTO users_tokens (user_id, access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, confirmation_token, confirmation_token_expires_at)
VALUES (
    (SELECT id FROM users WHERE email = '1kartofan@gmail.com'),
    'access_token_value',
    NOW() + INTERVAL '1 hour',
    'refresh_token_value',
    NOW() + INTERVAL '7 days',
    'confirmation_token_value',
    NOW() + INTERVAL '1 day'
);
-- +goose StatementEnd