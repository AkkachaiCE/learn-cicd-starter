package auth

import (
	"errors"
	"net/http"
	"testing"
)

// GetAPIKey units test
func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		{
			name:       "no auth header",
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed auth header",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			wantAPIKey: "hello",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name: "valid auth header",
			headers: http.Header{
				"Authorization": []string{"ApiKey hello123"},
			},
			wantAPIKey: "hello123",
			wantErr:    nil,
		},
	}

	for _, tc := range tests {
		gotKey, gotErr := GetAPIKey(tc.headers)

		if gotKey != tc.wantAPIKey || !errorsEqual(gotErr, tc.wantErr) {
			t.Fatalf("%s: expected key: %q, error: %v; got key: %q, error: %v",
				tc.name, tc.wantAPIKey, tc.wantErr, gotKey, gotErr)
		}
	}
}

// Helper function to compare errors safely
func errorsEqual(a, b error) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Error() == b.Error()
}
