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

package fake

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1alpha1 "kubeops.dev/scanner/apis/scanner/v1alpha1"
)

// FakeImageScanRequests implements ImageScanRequestInterface
type FakeImageScanRequests struct {
	Fake *FakeScannerV1alpha1
}

var imagescanrequestsResource = v1alpha1.SchemeGroupVersion.WithResource("imagescanrequests")

var imagescanrequestsKind = v1alpha1.SchemeGroupVersion.WithKind("ImageScanRequest")

// Get takes name of the imageScanRequest, and returns the corresponding imageScanRequest object, and an error if there is any.
func (c *FakeImageScanRequests) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ImageScanRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(imagescanrequestsResource, name), &v1alpha1.ImageScanRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ImageScanRequest), err
}

// List takes label and field selectors, and returns the list of ImageScanRequests that match those selectors.
func (c *FakeImageScanRequests) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ImageScanRequestList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(imagescanrequestsResource, imagescanrequestsKind, opts), &v1alpha1.ImageScanRequestList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ImageScanRequestList{ListMeta: obj.(*v1alpha1.ImageScanRequestList).ListMeta}
	for _, item := range obj.(*v1alpha1.ImageScanRequestList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested imageScanRequests.
func (c *FakeImageScanRequests) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(imagescanrequestsResource, opts))
}

// Create takes the representation of a imageScanRequest and creates it.  Returns the server's representation of the imageScanRequest, and an error, if there is any.
func (c *FakeImageScanRequests) Create(ctx context.Context, imageScanRequest *v1alpha1.ImageScanRequest, opts v1.CreateOptions) (result *v1alpha1.ImageScanRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(imagescanrequestsResource, imageScanRequest), &v1alpha1.ImageScanRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ImageScanRequest), err
}

// Update takes the representation of a imageScanRequest and updates it. Returns the server's representation of the imageScanRequest, and an error, if there is any.
func (c *FakeImageScanRequests) Update(ctx context.Context, imageScanRequest *v1alpha1.ImageScanRequest, opts v1.UpdateOptions) (result *v1alpha1.ImageScanRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(imagescanrequestsResource, imageScanRequest), &v1alpha1.ImageScanRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ImageScanRequest), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeImageScanRequests) UpdateStatus(ctx context.Context, imageScanRequest *v1alpha1.ImageScanRequest, opts v1.UpdateOptions) (*v1alpha1.ImageScanRequest, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(imagescanrequestsResource, "status", imageScanRequest), &v1alpha1.ImageScanRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ImageScanRequest), err
}

// Delete takes name of the imageScanRequest and deletes it. Returns an error if one occurs.
func (c *FakeImageScanRequests) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(imagescanrequestsResource, name, opts), &v1alpha1.ImageScanRequest{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeImageScanRequests) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(imagescanrequestsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.ImageScanRequestList{})
	return err
}

// Patch applies the patch and returns the patched imageScanRequest.
func (c *FakeImageScanRequests) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ImageScanRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(imagescanrequestsResource, name, pt, data, subresources...), &v1alpha1.ImageScanRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ImageScanRequest), err
}
