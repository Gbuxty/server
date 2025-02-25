package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Env             string         `yaml:"env"`
	StoragePath     string         `yaml:"storage_path"`
	AccessTokenTTL  time.Duration  `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration  `yaml:"refresh_token_ttl"`
	Grpc            *GRPCConfig    `yaml:"grpc"`
	JWT             *JWTConfig     `yaml:"jwt"`
	Mailopost       *MailopostConfig `yaml:"mailopost"` 
}
type GRPCConfig struct {
	Port    string        `yaml:"port"`
	TimeOut time.Duration `yaml:"timeout"`
}

type JWTConfig struct {
	SecretKey string `yaml:"secret_key"`
}

type MailopostConfig struct {
    ApiURL    string `yaml:"api_url"`
    ApiToken  string `yaml:"api_token"`
    FromEmail string `yaml:"from_email"`
}


func LoadConfig(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, err
}
