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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rest "k8s.io/client-go/rest"
	v1alpha1 "kubeops.dev/scanner/apis/cves/v1alpha1"
	scheme "kubeops.dev/scanner/client/clientset/versioned/scheme"
)

// ImageScanRequestsGetter has a method to return a ImageScanRequestInterface.
// A group's client should implement this interface.
type ImageScanRequestsGetter interface {
	ImageScanRequests() ImageScanRequestInterface
}

// ImageScanRequestInterface has methods to work with ImageScanRequest resources.
type ImageScanRequestInterface interface {
	Create(ctx context.Context, imageScanRequest *v1alpha1.ImageScanRequest, opts v1.CreateOptions) (*v1alpha1.ImageScanRequest, error)
	ImageScanRequestExpansion
}

// imageScanRequests implements ImageScanRequestInterface
type imageScanRequests struct {
	client rest.Interface
}

// newImageScanRequests returns a ImageScanRequests
func newImageScanRequests(c *CvesV1alpha1Client) *imageScanRequests {
	return &imageScanRequests{
		client: c.RESTClient(),
	}
}

// Create takes the representation of a imageScanRequest and creates it.  Returns the server's representation of the imageScanRequest, and an error, if there is any.
func (c *imageScanRequests) Create(ctx context.Context, imageScanRequest *v1alpha1.ImageScanRequest, opts v1.CreateOptions) (result *v1alpha1.ImageScanRequest, err error) {
	result = &v1alpha1.ImageScanRequest{}
	err = c.client.Post().
		Resource("imagescanrequests").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imageScanRequest).
		Do(ctx).
		Into(result)
	return
}
