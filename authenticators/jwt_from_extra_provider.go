package authenticators

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/common"
	goidc "github.com/coreos/go-oidc"
)

const bearerPrefix = "Bearer "

type JWTFromExtraProviderAuthenticator struct {
	headerName   string
	issuer       string
	isserName    string
	remoteKeySet goidc.KeySet
}

// This is not a full implementation of OIDC
// It *just* checks the token against the keys of an extra provider.
func NewJWTFromExtraProviderAuthenticator(
	headerName, issuer, issuerName, providerURL string) Authenticator {
	return &JWTFromExtraProviderAuthenticator{
		headerName:   headerName,
		issuer:       issuer,
		isserName:    issuerName,
		remoteKeySet: goidc.NewRemoteKeySet(context.Background(), providerURL+"/keys"),
	}
}

func (s *JWTFromExtraProviderAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*common.User, bool, error) {
	logger := common.RequestLogger(r, "JWT extra token authenticator")

	if len(r.Header[s.headerName]) != 1 {
		return nil, false, nil
	}

	rawIDToken := strings.TrimPrefix(r.Header[s.headerName][0], bearerPrefix)

	// Validate token
	verifier := goidc.NewVerifier(s.issuer, s.remoteKeySet, &goidc.Config{SkipClientIDCheck: true})
	jwt, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, false, err
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
		Name:   userID + ":" + s.isserName,
		Groups: groups,
	}
	return &user, true, nil
}

// Retrieve the USERID_CLAIM and the GROUPS_CLAIM from the JWT access token
func (s *JWTFromExtraProviderAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error) {

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
