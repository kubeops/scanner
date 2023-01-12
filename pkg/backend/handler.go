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

	"kubeops.dev/scanner/apis/trivy"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/nats-io/nats.go"
	"k8s.io/klog/v2"
)

func (mgr *Manager) getMessageQueueHandler() func(msg *nats.Msg) {
	getMarshalledResponse := func(resp *trivy.BackendResponse) ([]byte, error) {
		ret, err := trivy.JSON.Marshal(resp)
		if err != nil {
			return nil, err
		}
		return ret, nil
	}

	errorOnPrivateCheckingFunc := func(msg *nats.Msg, img string) {
		klog.Infof("Image %s is not pullable from scanner backend side", img)
		resp, err := getMarshalledResponse(&trivy.BackendResponse{
			Visibility: trivy.ImageVisibilityUnknown,
		})
		if err != nil {
			return
		}
		_ = msg.Respond(resp)
	}

	imageIsPrivateFunc := func(msg *nats.Msg) {
		resp, err := getMarshalledResponse(&trivy.BackendResponse{
			Visibility: trivy.ImageVisibilityPrivate,
		})
		if err != nil {
			return
		}
		_ = msg.Respond(resp)
	}

	reportExistsFunc := func(msg *nats.Msg, img string) {
		resp, err := mgr.getBucketResponse(img)
		if err != nil {
			return
		}

		marshalledResponse, err := getMarshalledResponse(resp)
		if err != nil {
			return
		}
		_ = msg.Respond(marshalledResponse)
	}

	submitForPublicFunc := func(msg *nats.Msg, img string) {
		err := mgr.submitScanRequest(img)
		if err != nil {
			return
		}
		resp, err := getMarshalledResponse(&trivy.BackendResponse{
			Visibility: trivy.ImageVisibilityPublic,
		})
		if err != nil {
			return
		}
		_ = msg.Respond(resp)
	}

	return func(msg *nats.Msg) {
		img := string(msg.Data)
		if img == "" {
			return
		}

		private, err := checkPrivateImage(img)
		if err != nil {
			errorOnPrivateCheckingFunc(msg, img)
			return
		}
		if private {
			imageIsPrivateFunc(msg)
			return
		}

		exists, err := ExistsReport(mgr.fs, img)
		if err != nil {
			return
		}
		if exists {
			reportExistsFunc(msg, img)
			return
		}
		submitForPublicFunc(msg, img)
	}
}

func checkPrivateImage(img string) (bool, error) {
	reference, err := name.ParseReference(img)
	if err != nil {
		return false, err
	}

	_, err = remote.Get(reference, remote.WithAuthFromKeychain(authn.DefaultKeychain))
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
