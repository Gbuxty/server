package logger

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"os"
)

// Logger — обёртка над zap.Logger для удобства использования.
type Logger struct {
	Logger *zap.Logger
}

// colorCode возвращает ANSI-код цвета для уровня логирования.
func colorCode(level zapcore.Level) string {
	switch level {
	case zapcore.DebugLevel:
		return "\033[36m" // Голубой
	case zapcore.InfoLevel:
		return "\033[32m" // Зелёный
	case zapcore.WarnLevel:
		return "\033[33m" // Жёлтый
	case zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		return "\033[31m" // Красный
	default:
		return "\033[0m" // Сброс цвета
	}
}

// coloredEncoder добавляет цвета к уровням логирования.
type coloredEncoder struct {
	zapcore.Encoder
}

// EncodeEntry добавляет цвет к сообщению лога.
func (e *coloredEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	// Добавляем цвет к уровню логирования
	entry.Message = fmt.Sprintf("%s%s\033[0m", colorCode(entry.Level), entry.Message)
	return e.Encoder.EncodeEntry(entry, fields)
}

// New создаёт новый логгер с цветным выводом.
func New() (*Logger, error) {
	// Настройка конфигурации логгера
	config := zap.NewProductionConfig()
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder // Формат времени
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // Цветные уровни

	// Создаём кастомный кодировщик
	encoder := zapcore.NewConsoleEncoder(config.EncoderConfig)
	colored := &coloredEncoder{Encoder: encoder}

	// Создаём логгер с кастомным кодировщиком
	core := zapcore.NewCore(colored, zapcore.AddSync(os.Stdout), zapcore.DebugLevel)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{Logger: logger}, nil
}

// Sync синхронизирует буферы логов.
func (l *Logger) Sync() {
	_ = l.Logger.Sync()
}