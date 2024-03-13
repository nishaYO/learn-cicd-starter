package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "Valid authorization header",
			headers:        http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedAPIKey: "abc123",
			expectedError:  nil,
		},
		{
			name:           "No authorization header included",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name:           "Malformed authorization header",
			headers:        http.Header{"Authorization": []string{"Bearer token"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError == nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("unexpected error: got %v, want %v", err, tt.expectedError)
			}

			if apiKey != tt.expectedAPIKey {
				t.Errorf("unexpected API key: got %s, want %s", apiKey, tt.expectedAPIKey)
			}
		})
	}
}
