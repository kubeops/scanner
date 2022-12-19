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

package backend

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func CheckPrivateImage(imageRef name.Reference) (bool, error) {
	_, err := remote.Get(imageRef, remote.WithAuth(authn.Anonymous))
	if err == nil {
		return false, nil
	}
	if strings.Contains(err.Error(), "UNAUTHORIZED") {
		return true, nil
	}
	if strings.Contains(err.Error(), "MANIFEST_UNKNOWN") { // If the image is kind loaded (not available online)
		return true, nil
	}
	return true, err
}
