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
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	v1alpha1 "kubeops.dev/scanner/apis/cves/v1alpha1"
	scheme "kubeops.dev/scanner/client/clientset/versioned/scheme"
)

// ImageScanReportsGetter has a method to return a ImageScanReportInterface.
// A group's client should implement this interface.
type ImageScanReportsGetter interface {
	ImageScanReports() ImageScanReportInterface
}

// ImageScanReportInterface has methods to work with ImageScanReport resources.
type ImageScanReportInterface interface {
	Create(ctx context.Context, imageScanReport *v1alpha1.ImageScanReport, opts v1.CreateOptions) (*v1alpha1.ImageScanReport, error)
	Update(ctx context.Context, imageScanReport *v1alpha1.ImageScanReport, opts v1.UpdateOptions) (*v1alpha1.ImageScanReport, error)
	UpdateStatus(ctx context.Context, imageScanReport *v1alpha1.ImageScanReport, opts v1.UpdateOptions) (*v1alpha1.ImageScanReport, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ImageScanReport, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ImageScanReportList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ImageScanReport, err error)
	ImageScanReportExpansion
}

// imageScanReports implements ImageScanReportInterface
type imageScanReports struct {
	client rest.Interface
}

// newImageScanReports returns a ImageScanReports
func newImageScanReports(c *CvesV1alpha1Client) *imageScanReports {
	return &imageScanReports{
		client: c.RESTClient(),
	}
}

// Get takes name of the imageScanReport, and returns the corresponding imageScanReport object, and an error if there is any.
func (c *imageScanReports) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ImageScanReport, err error) {
	result = &v1alpha1.ImageScanReport{}
	err = c.client.Get().
		Resource("imagescanreports").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ImageScanReports that match those selectors.
func (c *imageScanReports) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ImageScanReportList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ImageScanReportList{}
	err = c.client.Get().
		Resource("imagescanreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested imageScanReports.
func (c *imageScanReports) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("imagescanreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a imageScanReport and creates it.  Returns the server's representation of the imageScanReport, and an error, if there is any.
func (c *imageScanReports) Create(ctx context.Context, imageScanReport *v1alpha1.ImageScanReport, opts v1.CreateOptions) (result *v1alpha1.ImageScanReport, err error) {
	result = &v1alpha1.ImageScanReport{}
	err = c.client.Post().
		Resource("imagescanreports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imageScanReport).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a imageScanReport and updates it. Returns the server's representation of the imageScanReport, and an error, if there is any.
func (c *imageScanReports) Update(ctx context.Context, imageScanReport *v1alpha1.ImageScanReport, opts v1.UpdateOptions) (result *v1alpha1.ImageScanReport, err error) {
	result = &v1alpha1.ImageScanReport{}
	err = c.client.Put().
		Resource("imagescanreports").
		Name(imageScanReport.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imageScanReport).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *imageScanReports) UpdateStatus(ctx context.Context, imageScanReport *v1alpha1.ImageScanReport, opts v1.UpdateOptions) (result *v1alpha1.ImageScanReport, err error) {
	result = &v1alpha1.ImageScanReport{}
	err = c.client.Put().
		Resource("imagescanreports").
		Name(imageScanReport.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(imageScanReport).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the imageScanReport and deletes it. Returns an error if one occurs.
func (c *imageScanReports) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("imagescanreports").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *imageScanReports) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("imagescanreports").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched imageScanReport.
func (c *imageScanReports) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ImageScanReport, err error) {
	result = &v1alpha1.ImageScanReport{}
	err = c.client.Patch(pt).
		Resource("imagescanreports").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
