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

package v1alpha1

import (
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ResourceCodeImageScanRequest = "isreq"
	ResourceKindImageScanRequest = "ImageScanRequest"
	ResourceImageScanRequest     = "imagescanrequest"
	ResourceImageScanRequests    = "imagescanrequests"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ImageScanRequest struct {
	metav1.TypeMeta `json:",inline"`
	// Request describes the attributes for the graph request.
	// +optional
	Request *ImageScanRequestSpec `json:"request,omitempty"`
}

type ImageScanRequestSpec struct {
	ImageRef string `json:"imageRef"`
	// If some private image is referred in ImageRef, this field will contain the ImagePullSecrets from the pod template.
	// +optional
	PullSecrets []core.LocalObjectReference `json:"pullSecrets,omitempty"`
	// Namespace tells where to look for the image pull secrets.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}
