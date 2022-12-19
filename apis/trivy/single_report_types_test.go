/*
Copyright AppsCode Inc. and Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package trivy

import (
	"fmt"
	"reflect"
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
			err := RoundTripFile(tt.name, &SingleReport{})
			if (err != nil) != tt.wantErr {
				t.Errorf("RoundTripFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func RoundTripFile(filename string, v any) error {
	if reflect.TypeOf(v).Kind() != reflect.Pointer {
		return fmt.Errorf("v is expected to be a pointer, found %T", v)
	}

	original, err := tl.ReadFile(filename)
	if err != nil {
		return err
	}

	json := JSON
	err = json.Unmarshal(original, v)
	if err != nil {
		return err
	}
	nu, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return tl.DiffJSON(original, nu)
}
