package mailer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/badoux/checkmail"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type EmailBody struct {
	To     string `json:"to"`
	Action int    `json:"action"`
	Data   string `json:"data"`
	Locale string `json:"locale"`
}

// TemplateMailer will send mail and use templates from the site for easy mail styling
type MailService struct {
	SiteURL string
	Config  *conf.GlobalConfiguration
	Mailer  MailClient
}

func NewMailService(SiteURL string, Config *conf.GlobalConfiguration, Mailer MailClient) *MailService {
	return &MailService{SiteURL: SiteURL, Config: Config, Mailer: Mailer}
}

// ValidateEmail returns nil if the email is valid,
// otherwise an error indicating the reason it is invalid
func (m MailService) ValidateEmail(email string) error {
	return checkmail.ValidateFormat(email)
}

func closeBody(rsp *http.Response) {
	if rsp != nil && rsp.Body != nil {
		if err := rsp.Body.Close(); err != nil {
			logrus.WithError(err).Warn("body close in hooks failed")
		}
	}
}

func (m *MailService) sendEmail(payload []byte) error {
	logrus.Infof("sendEmail %s", m.Config.MailService.URL)
	client := http.Client{
		Timeout: time.Second * time.Duration(m.Config.MailService.Timeout),
	}

	payload = []byte(fmt.Sprintf("{\"data\": [%s]}", string(payload)))

	for i := 0; i < m.Config.MailService.Retries; i++ {
		req, err := http.NewRequest(http.MethodPost, m.Config.MailService.URL, bytes.NewBuffer(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		// logrus.Infof("sendEmail Payload %s", string(payload))
		rsp, err := client.Do(req)
		if err != nil {
			if terr, ok := err.(net.Error); ok && terr.Timeout() {
				// timed out - try again?
				if i == m.Config.MailService.Retries-1 {
					closeBody(rsp)
					return err
				}
				continue
			}
		} else {
			logrus.Infof("sendEmail Status %s", rsp.Status)
			break
		}
	}
	return nil
}

// InviteMail sends a invite mail to a new user
func (m *MailService) InviteMail(user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Invite, &EmailParams{
		Token:      user.ConfirmationToken,
		Type:       "invite",
		RedirectTo: referrerURL,
	})

	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.ConfirmationToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.Invite, "You have been invited"),
		m.Config.Mailer.Templates.Invite,
		defaultInviteMail,
		data,
	)
}

// ConfirmationMail sends a signup confirmation mail to a new user
func (m *MailService) ConfirmationMail(user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	logrus.Infof("ConfirmationMail")
	path, err := getPath(m.Config.Mailer.URLPaths.Confirmation, &EmailParams{
		Token:      user.ConfirmationToken,
		Type:       "signup",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	userName := user.UserMetaData["name"]
	body := &EmailBody{To: user.GetEmail(), Action: 12, Data: fmt.Sprintf("{\"username\":\"%s\",\"verifyUrl\":\"%s\"}", userName, externalURL.ResolveReference(path).String()), Locale: user.UserMetaData["locale"].(string)}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return m.sendEmail(payload)
}

// ReauthenticateMail sends a reauthentication mail to an authenticated user
func (m *MailService) ReauthenticateMail(user *models.User, otp string) error {
	data := map[string]interface{}{
		"SiteURL": m.Config.SiteURL,
		"Email":   user.Email,
		"Token":   otp,
		"Data":    user.UserMetaData,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.Reauthentication, "Confirm reauthentication"),
		m.Config.Mailer.Templates.Reauthentication,
		defaultReauthenticateMail,
		data,
	)
}

// EmailChangeMail sends an email change confirmation mail to a user
func (m *MailService) EmailChangeMail(user *models.User, otpNew, otpCurrent, referrerURL string, externalURL *url.URL) error {
	type Email struct {
		Address   string
		Otp       string
		TokenHash string
		Subject   string
		Template  string
	}
	emails := []Email{
		{
			Address:   user.EmailChange,
			Otp:       otpNew,
			TokenHash: user.EmailChangeTokenNew,
			Subject:   withDefault(m.Config.Mailer.Subjects.EmailChange, "Confirm Email Change"),
			Template:  m.Config.Mailer.Templates.EmailChange,
		},
	}

	currentEmail := user.GetEmail()
	if m.Config.Mailer.SecureEmailChangeEnabled && currentEmail != "" {
		emails = append(emails, Email{
			Address:   currentEmail,
			Otp:       otpCurrent,
			TokenHash: user.EmailChangeTokenCurrent,
			Subject:   withDefault(m.Config.Mailer.Subjects.Confirmation, "Confirm Email Address"),
			Template:  m.Config.Mailer.Templates.EmailChange,
		})
	}

	errors := make(chan error)
	for _, email := range emails {
		path, err := getPath(
			m.Config.Mailer.URLPaths.EmailChange,
			&EmailParams{
				Token:      email.TokenHash,
				Type:       "email_change",
				RedirectTo: referrerURL,
			},
		)
		if err != nil {
			return err
		}
		go func(address, token, tokenHash, template string) {
			data := map[string]interface{}{
				"SiteURL":         m.Config.SiteURL,
				"ConfirmationURL": externalURL.ResolveReference(path).String(),
				"Email":           user.GetEmail(),
				"NewEmail":        user.EmailChange,
				"Token":           token,
				"TokenHash":       tokenHash,
				"SendingTo":       address,
				"Data":            user.UserMetaData,
				"RedirectTo":      referrerURL,
			}
			errors <- m.Mailer.Mail(
				address,
				withDefault(m.Config.Mailer.Subjects.EmailChange, "Confirm Email Change"),
				template,
				defaultEmailChangeMail,
				data,
			)
		}(email.Address, email.Otp, email.TokenHash, email.Template)
	}

	for i := 0; i < len(emails); i++ {
		e := <-errors
		if e != nil {
			return e
		}
	}

	return nil
}

// RecoveryMail sends a password recovery mail
func (m *MailService) RecoveryMail(user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
		Token:      user.RecoveryToken,
		Type:       "recovery",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	userName := user.UserMetaData["name"]
	body := &EmailBody{To: user.GetEmail(), Action: 13, Data: fmt.Sprintf("{\"username\":\"%s\",\"resetPasswordUrl\":\"%s\"}", userName, externalURL.ResolveReference(path).String()), Locale: user.UserMetaData["locale"].(string)}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return m.sendEmail(payload)
}

// MagicLinkMail sends a login link mail
func (m *MailService) MagicLinkMail(user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
		Token:      user.RecoveryToken,
		Type:       "magiclink",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.RecoveryToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}

	return m.Mailer.Mail(
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.MagicLink, "Your Magic Link"),
		m.Config.Mailer.Templates.MagicLink,
		defaultMagicLinkMail,
		data,
	)
}

// Send can be used to send one-off emails to users
func (m MailService) Send(user *models.User, subject, body string, data map[string]interface{}) error {
	return m.Mailer.Mail(
		user.GetEmail(),
		subject,
		"",
		body,
		data,
	)
}

// GetEmailActionLink returns a magiclink, recovery or invite link based on the actionType passed.
func (m MailService) GetEmailActionLink(user *models.User, actionType, referrerURL string, externalURL *url.URL) (string, error) {
	var err error
	var path *url.URL

	switch actionType {
	case "magiclink":
		path, err = getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
			Token:      user.RecoveryToken,
			Type:       "magiclink",
			RedirectTo: referrerURL,
		})
	case "recovery":
		path, err = getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
			Token:      user.RecoveryToken,
			Type:       "recovery",
			RedirectTo: referrerURL,
		})
	case "invite":
		path, err = getPath(m.Config.Mailer.URLPaths.Invite, &EmailParams{
			Token:      user.ConfirmationToken,
			Type:       "invite",
			RedirectTo: referrerURL,
		})
	case "signup":
		path, err = getPath(m.Config.Mailer.URLPaths.Confirmation, &EmailParams{
			Token:      user.ConfirmationToken,
			Type:       "signup",
			RedirectTo: referrerURL,
		})
	case "email_change_current":
		path, err = getPath(m.Config.Mailer.URLPaths.EmailChange, &EmailParams{
			Token:      user.EmailChangeTokenCurrent,
			Type:       "email_change",
			RedirectTo: referrerURL,
		})
	case "email_change_new":
		path, err = getPath(m.Config.Mailer.URLPaths.EmailChange, &EmailParams{
			Token:      user.EmailChangeTokenNew,
			Type:       "email_change",
			RedirectTo: referrerURL,
		})
	default:
		return "", fmt.Errorf("invalid email action link type: %s", actionType)
	}
	if err != nil {
		return "", err
	}
	return externalURL.ResolveReference(path).String(), nil
}
