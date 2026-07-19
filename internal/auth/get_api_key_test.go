package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		// A generic function to validate the error rule for each case
		errCheck func(error) bool
	}{
		{
			name:        "Valid ApiKey header",
			authHeader:  "ApiKey super-secret-shared-key",
			expectedKey: "super-secret-shared-key",
			errCheck:    func(err error) bool { return err == nil },
		},
		{
			name:        "Missing Authorization header",
			authHeader:  "",
			expectedKey: "",
			// Actively uses the "errors" package to check your sentinel error
			errCheck: func(err error) bool { return errors.Is(err, ErrNoAuthHeaderIncluded) },
		},
		{
			name:        "Malformed header",
			authHeader:  "just-a-token",
			expectedKey: "",
			errCheck:    func(err error) bool { return err != nil && err.Error() == "malformed authorization header" },
		},
		{
			name:        "Wrong scheme",
			authHeader:  "Bearer some-token",
			expectedKey: "",
			errCheck:    func(err error) bool { return err != nil && err.Error() == "malformed authorization header" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			// Generic evaluation: No if/else cluttering up the runner loop!
			if !tt.errCheck(err) {
				t.Errorf("error validation failed for %q, got error: %v", tt.name, err)
			}

			if gotKey != tt.expectedKey {
				t.Errorf("got key %q, want %q", gotKey, tt.expectedKey)
			}
		})
	}
}
