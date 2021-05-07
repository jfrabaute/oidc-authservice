package main

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/api/idtoken"
)

type gcpAuthenticator struct {
	requestHeader string
	validator     *idtoken.Validator
}

func newGcpAuthenticator(header string) (*gcpAuthenticator, error) {
	// XXX should probably be using a real context
	ctx := context.Background()
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating validator: %v", err)
	}

	g := &gcpAuthenticator{
		requestHeader: header,
		validator:     validator,
	}
	return g, nil
}

func (ga *gcpAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	logger := loggerForRequest(r)

	// get service account token from header
	token := getBearerToken(r.Header.Get(ga.requestHeader))
	if token == "" {
		return nil, nil
	}

	// XXX should probably be using a real context
	ctx := context.Background()
	// TODO could make audience a configurable field
	payload, err := ga.validator.Validate(ctx, token, "")
	if err != nil {
		logger.Errorf("error while validating gcp idtoken: %v", err)
	}
	if payload == nil {
		return nil, nil
	}

	resp := &User{
		Name: payload.Claims["email"].(string),
	}
	return resp, nil
}
