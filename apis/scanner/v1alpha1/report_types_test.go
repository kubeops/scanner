package v1alpha1

import (
	"testing"

	tl "gomodules.xyz/testing"
)

func TestReport(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "hack/examples/ubuntu.json",
			wantErr: false,
		},
		{
			name:    "hack/examples/haproxy.json",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tl.RoundTripFile(tt.name, &Report{})
			if (err != nil) != tt.wantErr {
				t.Errorf("RoundTripFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
