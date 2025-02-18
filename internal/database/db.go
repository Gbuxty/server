package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func NewDB(conntStr string) (*pgxpool.Pool, error) {

	var err error

	DB, err = pgxpool.New(context.Background(), conntStr)
	if err != nil {
		return nil, fmt.Errorf("bad connect to db %w", err)
	}

	return DB, nil
}

func CloseDb() {
	if DB != nil {
		DB.Close()
	}
}
