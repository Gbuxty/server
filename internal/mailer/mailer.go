package mailer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"server/internal/logger"

	"go.uber.org/zap"
)

type Mailer struct {
	ApiURL    string
	ApiToken  string
	FromEmail string
	logger    *logger.Logger
}

func NewMailer(ApiURL, ApiToken, FromEmail string, logger *logger.Logger) *Mailer {
	return &Mailer{ApiURL: ApiURL, ApiToken: ApiToken, FromEmail: FromEmail, logger: logger}
}

func (m *Mailer) SendEmail(toEmail, subject, body string) error {
	m.logger.Logger.Info("Sending email",
		zap.String("to", toEmail),
		zap.String("subject", subject),
	)

	emailData := map[string]string{
		"from_email": m.FromEmail,
		"to":         toEmail,
		"subject":    subject,
		"text":       body,
	}

	jsonData, err := json.Marshal(emailData)
	if err != nil {
		m.logger.Logger.Error("failed to marshal email data", zap.Error(err))
		return fmt.Errorf("failed to marshal email data: %w", err)
	}

	req, err := http.NewRequest("POST", m.ApiURL+"/email/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		m.logger.Logger.Error("failed to create email request", zap.Error(err))
		return fmt.Errorf("failed to create email request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.ApiToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		m.logger.Logger.Error("failed to send email", zap.Error(err))
		return fmt.Errorf("failed to send email: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		m.logger.Logger.Error("failed to send email", zap.Error(err))
		return fmt.Errorf("failed to send email, status code: %d", resp.StatusCode)
	}

	m.logger.Logger.Info("Email sent successfully",
		zap.String("to", toEmail),
	)
	return nil
}
