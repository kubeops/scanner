/*
Copyright AppsCode Inc. and Contributors

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ResourceKindScanSummary = "ScanSummary"
	ResourceScanSummary     = "scansummary"
	ResourceScanSummaries   = "scansummaries"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=scansummaries,singular=scansummary,scope=Cluster
type ScanSummary struct {
	metav1.TypeMeta `json:",inline"`
	// Request describes the attributes for the graph request.
	// +optional
	Request *ScanSummaryRequest `json:"request,omitempty"`
	// Response describes the attributes for the graph response.
	// +optional
	Response *ScanSummaryResponse `json:"response,omitempty"`
}

type ScanSummaryRequest struct {
	ImageRef string `json:"imageRef"`
}

type ScanSummaryResponse struct {
	Result Summary `json:"result"`
}
