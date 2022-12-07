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
	v1alpha1 "kubeops.dev/scanner/apis/scanner/v1alpha1"
	scheme "kubeops.dev/scanner/client/clientset/versioned/scheme"
)

// ScanReportsGetter has a method to return a ScanReportInterface.
// A group's client should implement this interface.
type ScanReportsGetter interface {
	ScanReports() ScanReportInterface
}

// ScanReportInterface has methods to work with ImageScanRequest resources.
type ScanReportInterface interface {
	Create(ctx context.Context, scanReport *v1alpha1.ImageScanRequest, opts v1.CreateOptions) (*v1alpha1.ImageScanRequest, error)
	ScanReportExpansion
}

// scanReports implements ScanReportInterface
type scanReports struct {
	client rest.Interface
}

// newScanReports returns a ScanReports
func newScanReports(c *ScannerV1alpha1Client) *scanReports {
	return &scanReports{
		client: c.RESTClient(),
	}
}

// Create takes the representation of a scanReport and creates it.  Returns the server's representation of the scanReport, and an error, if there is any.
func (c *scanReports) Create(ctx context.Context, scanReport *v1alpha1.ImageScanRequest, opts v1.CreateOptions) (result *v1alpha1.ImageScanRequest, err error) {
	result = &v1alpha1.ImageScanRequest{}
	err = c.client.Post().
		Resource("scanreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(scanReport).
		Do(ctx).
		Into(result)
	return
}
