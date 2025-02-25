package mailer

import (
	"bytes"
	"encoding/json"
	"fmt"

	"net/http"
)

type Mailer struct {
	ApiURL    string
	ApiToken  string
	FromEmail string
}

func NewMailer(ApiURL, ApiToken, FromEmail string) *Mailer {
	return &Mailer{ApiURL: ApiURL, ApiToken: ApiToken, FromEmail: FromEmail}
}

func (m *Mailer) SendEmail(toEmail, subject, body string) error {
	emailData := map[string]string{
		"from_email": m.FromEmail,
		"to":         toEmail,
		"subject":    subject,
		"text":       body,
	}

	jsonData, err := json.Marshal(emailData)
	if err != nil {
		return fmt.Errorf("failed to marshal email data: %w", err)
	}

	req, err := http.NewRequest("POST", m.ApiURL+"/email/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create email request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.ApiToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("failed to send email, status code: %d", resp.StatusCode)
	}

	return nil
}
