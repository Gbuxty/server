DB_DSN=postgres://postgres:postgres_1234@localhost:5445/Authentication?sslmode=disable
MIGRATIONS_DIR=./migrations/postgres

# Генерация protobuf
gen-proto:
	protoc --go_out=./proto/ --go-grpc_out=./proto/ ./proto/authentication.proto

# Запуск приложения
run:
	go run ./cmd/main.go

# Создание новой миграции
migrate_create_%:
	goose -dir $(MIGRATIONS_DIR) create $(subst migrate_create_,,$@) sql

# Применение миграций
migrate_up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_DSN)" up

# Откат последней миграции
migrate_down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_DSN)" down

# Откат всех миграций
migrate_reset:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_DSN)" reset

# Просмотр статуса миграций
migrate_status:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_DSN)" status

# Сборка Docker-образа
docker-build:
	docker build -t your-app-name .

# Запуск Docker-контейнера
docker-run:
	docker run -p 9090:9090 your-app-name

# Запуск docker-compose
docker-compose-up:
	docker-compose up --build

# Показать справку
help:
	@echo "Доступные команды:"
	@echo "  gen-proto          - Генерация protobuf"
	@echo "  run                - Запуск приложения"
	@echo "  migrate_create_%   - Создать новую миграцию (замените % на имя миграции)"
	@echo "  migrate_up         - Применить миграции"
	@echo "  migrate_down       - Откатить последнюю миграцию"
	@echo "  migrate_reset      - Откатить все миграции"
	@echo "  migrate_status     - Показать статус миграций"
	@echo "  docker-build       - Собрать Docker-образ"
	@echo "  docker-run         - Запустить Docker-контейнер"
	@echo "  docker-compose-up  - Запустить docker-compose"
	@echo "  help               - Показать эту справку"