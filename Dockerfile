# Используем базовый образ Go для сборки
FROM golang:1.22-alpine AS builder

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы зависимостей
COPY go.mod go.sum ./

# Скачиваем зависимости
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/main.go

# Используем минимальный образ Alpine для финального контейнера
FROM alpine:latest

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем собранное приложение из builder
COPY --from=builder /server /server

# Копируем файл конфигурации из internal/config в config
COPY internal/config/local.yaml ./config/local.yaml

# Указываем команду для запуска приложения
CMD ["/server"]