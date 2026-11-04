package main

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"log"
	"net/mail"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

const maxEmailLen = 254 // RFC 5321 path limit

// message is one outgoing email: plain text plus a simple HTML copy, with no
// images, links to elsewhere or tracking of any kind.
type message struct {
	to      string
	subject string
	text    string
	html    string
}

// mailer sends one message. sesMailer is the real one; logMailer (local runs
// and CI only) writes messages to the log instead.
type mailer interface {
	send(ctx context.Context, m message) error
}

type sesMailer struct {
	client *sesv2.Client
	from   string
}

func newSESMailer(ctx context.Context, region, from string) (*sesMailer, error) {
	// The default chain: on EC2 that is the instance role, which may send only
	// as no-reply@ (see deploy/shortened.yaml).
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return &sesMailer{client: sesv2.NewFromConfig(cfg), from: from}, nil
}

func (m *sesMailer) send(ctx context.Context, msg message) error {
	utf8 := aws.String("UTF-8")
	_, err := m.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(m.from),
		Destination:      &sestypes.Destination{ToAddresses: []string{msg.to}},
		Content: &sestypes.EmailContent{Simple: &sestypes.Message{
			Subject: &sestypes.Content{Data: aws.String(msg.subject), Charset: utf8},
			Body: &sestypes.Body{
				Text: &sestypes.Content{Data: aws.String(msg.text), Charset: utf8},
				Html: &sestypes.Content{Data: aws.String(msg.html), Charset: utf8},
			},
		}},
	})
	return err
}

// logMailer prints messages, codes included, so the app can be tried locally
// and in CI without SES. It is used only when MAIL_LOG=true and MAIL_FROM is
// empty; a deployment always sets MAIL_FROM.
type logMailer struct{}

func (logMailer) send(_ context.Context, m message) error {
	log.Printf("MAIL_LOG to=%s subject=%q\n%s", m.to, m.subject, m.text)
	return nil
}

// sendMail hands a message to the mailer in the background. Answers must not
// wait on (or time) the mail service: a forgot-password request for a real
// account would otherwise take longer than one for a made-up name. Failures
// are logged; the user can ask for another code.
func (s *server) sendMail(m message) {
	s.mailWG.Add(1)
	go func() {
		defer s.mailWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.mailer.send(ctx, m); err != nil {
			log.Printf("send mail (%s): %v", m.subject, err)
		}
	}()
}

// normalizeEmail returns the address in lower case, or an error if it is not
// a plain address like name@example.com.
func normalizeEmail(raw string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(raw))
	bad := errors.New("enter a valid email address, like name@example.com")
	if e == "" || len(e) > maxEmailLen {
		return "", bad
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" {
		return "", bad
	}
	at := strings.LastIndexByte(e, '@')
	if at < 1 || !strings.Contains(e[at+1:], ".") || strings.ContainsAny(e, " <>\"(),;:[]\\") {
		return "", bad
	}
	return e, nil
}

var mailHTML = template.Must(template.New("mail").Parse(`<!doctype html>
<html><body style="font-family:Arial,Helvetica,sans-serif;color:#111;max-width:480px">
<p style="font-size:18px;font-weight:bold">SHORTENED.</p>
{{range .Lines}}<p>{{.}}</p>
{{end}}{{if .Code}}<p style="font-family:monospace;font-size:28px;letter-spacing:6px;font-weight:bold">{{.Code}}</p>
{{end}}<p style="color:#666;font-size:12px">{{.Footer}}</p>
</body></html>`))

// buildMessage renders the text and HTML bodies from the same lines. Code, if
// set, is shown on its own after the lines.
func buildMessage(to, subject string, lines []string, code, footer string) message {
	var text strings.Builder
	for _, l := range lines {
		text.WriteString(l + "\n\n")
	}
	if code != "" {
		text.WriteString("    " + code + "\n\n")
	}
	text.WriteString("-- \n" + footer + "\n")

	var html bytes.Buffer
	if err := mailHTML.Execute(&html, struct {
		Lines        []string
		Code, Footer string
	}{lines, code, footer}); err != nil {
		log.Printf("render mail: %v", err) // can't happen with these fixed types
	}
	return message{to: to, subject: subject, text: text.String(), html: html.String()}
}

const mailFooter = "You get this because this address was entered on SHORTENED. If that wasn't you, ignore this email; nothing changes without the code."

func verifyMessage(to, username, code string) message {
	return buildMessage(to, "Your SHORTENED. verification code",
		[]string{
			"Hi " + username + ",",
			"Enter this code to confirm your email address. It works for 10 minutes.",
		}, code, mailFooter)
}

func resetMessage(to, username, code string) message {
	return buildMessage(to, "Your SHORTENED. password reset code",
		[]string{
			"Hi " + username + ",",
			"Someone asked to reset the password of your account. Enter this code with your new password. It works for 10 minutes.",
			"Resetting signs out every other session.",
		}, code, mailFooter)
}

// inUseMessage goes to an address that already belongs to a verified account
// when someone enters it again, instead of a code. The answer on the page is
// the same either way, so the page never reveals that the address is taken.
// deletedMessage confirms that an account and its files are gone.
func deletedMessage(to, username string) message {
	return buildMessage(to, "Your SHORTENED. account is deleted",
		[]string{
			"The account " + username + " and every file in it have been deleted, as you asked.",
			"Nothing of it is kept. If this wasn't you, someone knew your password: use a new one wherever you used it.",
		}, "", mailFooter)
}

func inUseMessage(to string) message {
	return buildMessage(to, "Your address is already on SHORTENED.",
		[]string{
			"Someone tried to use this address for another SHORTENED. account, but it already belongs to one.",
			"If that was you, sign in with your username or this address, or use \"Forgot password\".",
		}, "", mailFooter)
}
