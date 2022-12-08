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

package request

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"time"

	api "kubeops.dev/scanner/apis/cves/v1alpha1"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/nats-io/nats.go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ImageRequest struct {
	cid string
	nc  *nats.Conn
	cl  client.Client
}

var (
	_ rest.GroupVersionKindProvider = &ImageRequest{}
	_ rest.Scoper                   = &ImageRequest{}
	_ rest.Creater                  = &ImageRequest{}
	_ rest.Storage                  = &ImageRequest{}
)

func NewScanReportStorage(cid string, nc *nats.Conn, cl client.Client) *ImageRequest {
	s := &ImageRequest{
		cid: cid,
		nc:  nc,
		cl:  cl,
	}
	return s
}

func (r *ImageRequest) GroupVersionKind(_ schema.GroupVersion) schema.GroupVersionKind {
	return api.SchemeGroupVersion.WithKind(api.ResourceKindImageScanRequest)
}

func (r *ImageRequest) NamespaceScoped() bool {
	return false
}

func (r *ImageRequest) New() runtime.Object {
	return &api.ImageScanRequest{}
}

func (r *ImageRequest) Destroy() {}

func (r *ImageRequest) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, createOpts *metav1.CreateOptions) (runtime.Object, error) {
	in := obj.(*api.ImageScanRequest)

	msg, err := r.nc.Request("scanner.report", []byte(in.Request.ImageRef), backend.NatsRequestTimeout)
	if err != nil {
		return nil, err
	}

	var report api.SingleReport
	err = json.Unmarshal(msg.Data, &report)
	if err != nil {
		return nil, err
	}

	isrep := api.ImageScanReport{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.ResourceKindImageScanReport,
			APIVersion: api.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%x", md5.Sum([]byte(in.Request.ImageRef))),
		},
		Spec: api.ImageScanReportSpec{
			Image: in.Request.ImageRef,
			// TODO: How can we modify the tag & digest field ?
		},
		Status: api.ImageScanReportStatus{
			LastChecked: api.MyTime(metav1.Time{Time: time.Now()}),
			Report:      report,
		},
	}

	err = r.cl.Create(context.TODO(), &isrep, &client.CreateOptions{
		Raw: createOpts,
	})
	return obj, err
}
