package main

import "testing"

func TestExtractUsernameFromSubject(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		expected string
	}{
		{
			name:     "Simple username",
			subject:  "user1",
			expected: "user1",
		},
		{
			name:     "Slash-separated DN with CN and UID",
			subject:  "/CN=user1/UID=user1",
			expected: "user1",
		},
		{
			name:     "Comma-separated DN with UID and CN",
			subject:  "UID=user1,CN=user1",
			expected: "user1",
		},
		{
			name:     "Full DN with email",
			subject:  "emailAddress=user1@home.arpa,CN=user1,OU=Users,O=Lake,L=Tualatin,ST=OR,C=US",
			expected: "user1",
		},
		{
			name:     "Slash-separated DN with only CN",
			subject:  "/CN=testuser",
			expected: "testuser",
		},
		{
			name:     "Comma-separated DN with only CN",
			subject:  "CN=testuser",
			expected: "testuser",
		},
		{
			name:     "Slash-separated DN with UID priority",
			subject:  "/CN=user1/UID=user2",
			expected: "user2", // UID takes priority
		},
		{
			name:     "Comma-separated DN with UID priority",
			subject:  "CN=user1,UID=user2",
			expected: "user2", // UID takes priority
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractUsernameFromSubject(tt.subject)
			if result != tt.expected {
				t.Errorf("extractUsernameFromSubject(%q) = %q, want %q", tt.subject, result, tt.expected)
			}
		})
	}
}
