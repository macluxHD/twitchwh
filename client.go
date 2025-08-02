// Package twitchwh is a library for interacting with Twitch EventSub over the Webhook transport.
// It allows you to assign event handlers to specific events.
//
// To get started, create a new client using the New function. Then, assign an event handler using the On<EventType> fields.
// Finally, setup the HTTP handler for your application using the Handler function.
package twitchwh

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"
)

type HandledEventsChecker interface {
	IsHandled(messageID string) bool
	MarkHandled(messageID string)
}

type DefaultHandledEventsChecker struct {
	mu            sync.RWMutex
	handledEvents []string
}

func NewDefaultHandledEventsChecker() *DefaultHandledEventsChecker {
	return &DefaultHandledEventsChecker{
		handledEvents: make([]string, 0),
	}
}

func (d *DefaultHandledEventsChecker) IsHandled(messageID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return slices.Contains(d.handledEvents, messageID)
}

func (d *DefaultHandledEventsChecker) MarkHandled(messageID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handledEvents = append(d.handledEvents, messageID)
}

// ClientConfig is used to configure a new Client
type ClientConfig struct {
	// Client ID of your Twitch application
	ClientID string
	// Client Secret generated for your Twitch application. !! THIS IS NOT YOUR WEBHOOK SECRET !!
	ClientSecret string
	// Webhook secret used to verify events. This should be a random string between 10-100 characters
	WebhookSecret string
	// Full EventSub URL path, eg: https://mydomain.com/eventsub
	WebhookURL string
	// Log output
	Debug                bool
	HandledEventsChecker HandledEventsChecker
}

type Client struct {
	clientID      string
	clientSecret  string
	token         string
	webhookSecret string
	webhookURL    string
	debug         bool

	logger               *log.Logger
	httpClient           *http.Client
	handledEventsChecker HandledEventsChecker
	// Client.Handler sends verified IDs to this channel to be read in Client.AddSubscription
	verifiedSubscriptions chan string

	// Fired whenever a subscription is revoked.
	// Check Subscription.Status for the reason.
	OnRevocation func(Subscription)
	handlers     map[string]func(json.RawMessage)
}

// Assign a handler to a particular event type. The handler takes a json.RawMessage that contains the event body.
// For a list of event types, see [https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/].
func (c *Client) On(event string, handler func(json.RawMessage)) {
	c.handlers[event] = handler
}

// Creates a new client
func New(config ClientConfig) (*Client, error) {
	handledEventsChecker := config.HandledEventsChecker
	if handledEventsChecker == nil {
		handledEventsChecker = NewDefaultHandledEventsChecker()
	}

	c := &Client{
		clientID:              config.ClientID,
		clientSecret:          config.ClientSecret,
		webhookSecret:         config.WebhookSecret,
		webhookURL:            config.WebhookURL,
		logger:                log.New(os.Stdout, "TwitchWH: ", log.Ltime|log.Lmicroseconds),
		debug:                 config.Debug,
		httpClient:            &http.Client{},
		handledEventsChecker:  handledEventsChecker,
		verifiedSubscriptions: make(chan string),
		handlers:              make(map[string]func(json.RawMessage)),
	}

	// Disable logging if debug is false
	if !c.debug {
		c.logger.SetOutput(io.Discard)
	}

	c.logger.Println("Generating token")
	token, err := c.generateToken(c.clientID, c.clientSecret)
	if err != nil {
		return nil, err
	}
	c.logger.Println("Token generated")
	c.token = token
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			valid, err := c.validateToken(c.token)
			if err != nil {
				c.logger.Printf("Could not validate token: %s", err)
				continue
			}
			if !valid {
				c.logger.Println("Token invalid, generating a new one")
				token, err := c.generateToken(c.clientID, c.clientSecret)
				if err != nil {
					c.logger.Printf("Could not generate token: %s", err)
					continue
				}
				c.token = token
			}
		}
	}()

	return c, nil
}
