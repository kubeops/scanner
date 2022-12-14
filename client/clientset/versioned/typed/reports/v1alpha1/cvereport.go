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
	v1alpha1 "kubeops.dev/scanner/apis/reports/v1alpha1"
	scheme "kubeops.dev/scanner/client/clientset/versioned/scheme"
)

// CVEReportsGetter has a method to return a CVEReportInterface.
// A group's client should implement this interface.
type CVEReportsGetter interface {
	CVEReports() CVEReportInterface
}

// CVEReportInterface has methods to work with CVEReport resources.
type CVEReportInterface interface {
	Create(ctx context.Context, cVEReport *v1alpha1.CVEReport, opts v1.CreateOptions) (*v1alpha1.CVEReport, error)
	CVEReportExpansion
}

// cVEReports implements CVEReportInterface
type cVEReports struct {
	client rest.Interface
}

// newCVEReports returns a CVEReports
func newCVEReports(c *ReportsV1alpha1Client) *cVEReports {
	return &cVEReports{
		client: c.RESTClient(),
	}
}

// Create takes the representation of a cVEReport and creates it.  Returns the server's representation of the cVEReport, and an error, if there is any.
func (c *cVEReports) Create(ctx context.Context, cVEReport *v1alpha1.CVEReport, opts v1.CreateOptions) (result *v1alpha1.CVEReport, err error) {
	result = &v1alpha1.CVEReport{}
	err = c.client.Post().
		Resource("cvereports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(cVEReport).
		Do(ctx).
		Into(result)
	return
}
