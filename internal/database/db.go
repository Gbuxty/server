package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)


type Database struct{
	Conn *pgxpool.Pool
}

func NewDB(conntStr string) (*Database, error) {


	DB, err := pgxpool.New(context.Background(), conntStr)
	if err != nil {
		return nil, fmt.Errorf("can not connect to db %w", err)
	}

	return &Database{
		Conn: DB,
	},nil
}

func (d *Database)CloseDb() {
	d.Conn.Close()
}
