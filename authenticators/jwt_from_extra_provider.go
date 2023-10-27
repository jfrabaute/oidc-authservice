package authenticators

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/arrikto/oidc-authservice/common"
	goidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"k8s.io/utils/strings/slices"
)

const bearerPrefix = "Bearer "

type jwtFromExtraProviderAuthenticator struct {
	headerName   string
	issuer       string
	issuerName   string
	clientID     string
	remoteKeySet goidc.KeySet
}

// This is not a full implementation of OIDC
// It *just* checks the token against the keys of an extra provider.
func NewJWTFromExtraProviderAuthenticator(
	headerName, issuer, issuerName, clientID string,
	providerURL *url.URL) (Authenticator, error) {

	if !slices.Contains([]string{"http", "https"}, providerURL.Scheme) {
		return nil, fmt.Errorf(
			"Error creating jwt from extra provider authenticator: "+
				"provider URL is incorrect: %s",
			providerURL.String())
	}
	if headerName == "" {
		return nil, errors.New(
			"Error creating jwt from extra provider authenticator: header name is empty")
	}
	if clientID == "" {
		return nil, errors.New(
			"Error creating jwt from extra provider authenticator: clientID is empty")
	}

	return &jwtFromExtraProviderAuthenticator{
		headerName:   headerName,
		issuer:       issuer,
		issuerName:   issuerName,
		clientID:     clientID,
		remoteKeySet: goidc.NewRemoteKeySet(context.Background(), providerURL.String()+"/keys"),
	}, nil
}

func (s *jwtFromExtraProviderAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*common.User, bool, error) {
	logger := common.RequestLogger(r, "JWT extra token authenticator")

	if len(r.Header[s.headerName]) != 1 {
		return nil, false, nil
	}

	rawIDToken := strings.TrimPrefix(r.Header[s.headerName][0], bearerPrefix)

	// Validate token
	verifier := goidc.NewVerifier(s.issuer, s.remoteKeySet, &goidc.Config{ClientID: s.clientID})
	jwt, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, false, &common.AuthenticatorSpecificError{Err: err}
	}
	// Retrieve the USERID_CLAIM and the GROUPS_CLAIM
	var claims map[string]interface{}
	if claimErr := jwt.Claims(&claims); claimErr != nil {
		logger.Errorf("Retrieving user claims failed: %v", claimErr)
		return nil, false, &common.AuthenticatorSpecificError{Err: claimErr}
	}
	userID, groups, claimErr := s.retrieveUserIDGroupsClaims(claims)
	if claimErr != nil {
		return nil, false, &common.AuthenticatorSpecificError{Err: claimErr}
	}

	user := common.User{
		Name:   userID + ":" + s.issuerName,
		Groups: groups,
	}
	return &user, true, nil
}

// Retrieve the USERID_CLAIM and the GROUPS_CLAIM from the JWT access token
func (s *jwtFromExtraProviderAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error) {

	if claims["email"] == nil {
		claimErr := fmt.Errorf("USERID_CLAIM not found in the JWT token")
		return "", []string{}, claimErr
	}

	var groups []string
	groupsClaim := claims["groups"]
	if groupsClaim == nil {
		claimErr := fmt.Errorf("GROUPS_CLAIM not found in the JWT token")
		return "", []string{}, claimErr
	}

	groups = common.InterfaceSliceToStringSlice(groupsClaim.([]interface{}))

	return claims["email"].(string), groups, nil
}
