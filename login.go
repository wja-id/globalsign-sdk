package globalsign

import (
	"context"
	"net/http"
)

// LoginRequest .
type LoginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// LoginResponse .
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

// LoginService .
type LoginService interface {
	Login(context.Context, *LoginRequest) (*LoginResponse, *Response, error)
}

type loginService struct {
	client *Client
}

func (s *loginService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, *Response, error) {
	// ensure params not nil
	if req == nil {
		req = &LoginRequest{}
	}

	path := baseAPI + "/login"
	r, err := s.client.NewRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, nil, err
	}

	result := new(LoginResponse)
	resp, err := s.client.Do(ctx, r, result)
	if err != nil {
		return nil, resp, err
	}

	return result, resp, nil
}
