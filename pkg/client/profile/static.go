package profile

import (
	"net/http"
	"time"

	"github.com/zitadel/oidc/pkg/client"
	"golang.org/x/oauth2"
)

// staticTokenSource implement the oauth2.TokenSource with static access token
type staticTokenSource struct {
	accessToken   string
	tokenType     string
	refreshToken  string
	expiry        time.Time
	httpClient    *http.Client
	tokenEndpoint string
}

func NewStaticTokenSource(issuer string, token oauth2.Token, options ...func(source *staticTokenSource)) (oauth2.TokenSource, error) {
	source := &staticTokenSource{
		accessToken:  token.AccessToken,
		tokenType:    token.TokenType,
		refreshToken: token.RefreshToken,
		expiry:       token.Expiry,
		httpClient:   http.DefaultClient,
	}
	for _, opt := range options {
		opt(source)
	}
	if source.tokenEndpoint == "" {
		config, err := client.Discover(issuer, source.httpClient)
		if err != nil {
			return nil, err
		}
		source.tokenEndpoint = config.TokenEndpoint
	}
	return source, nil
}

func (p *staticTokenSource) TokenEndpoint() string {
	return p.tokenEndpoint
}

func (p *staticTokenSource) HttpClient() *http.Client {
	return p.httpClient
}

func (p *staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  p.accessToken,
		TokenType:    p.tokenType,
		RefreshToken: p.refreshToken,
		Expiry:       p.expiry,
	}, nil
}
