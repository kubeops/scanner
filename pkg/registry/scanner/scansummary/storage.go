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

package scansummary

import (
	"context"
	"encoding/json"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/nats-io/nats.go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
)

type Storage struct {
	cid string
	nc  *nats.Conn
}

var (
	_ rest.GroupVersionKindProvider = &Storage{}
	_ rest.Scoper                   = &Storage{}
	_ rest.Creater                  = &Storage{}
	_ rest.Storage                  = &Storage{}
)

func NewStorage(cid string, nc *nats.Conn) *Storage {
	s := &Storage{
		cid: cid,
		nc:  nc,
	}
	return s
}

func (r *Storage) GroupVersionKind(_ schema.GroupVersion) schema.GroupVersionKind {
	return api.SchemeGroupVersion.WithKind(api.ResourceKindScanSummary)
}

func (r *Storage) NamespaceScoped() bool {
	return false
}

func (r *Storage) New() runtime.Object {
	return &api.ScanSummary{}
}

func (r *Storage) Destroy() {}

func (r *Storage) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	in := obj.(*api.ScanSummary)

	msg, err := r.nc.Request("scanner.summary", []byte(in.Request.ImageRef), backend.NatsRequestTimeout)
	if err != nil {
		return nil, err
	}

	var summary api.Summary
	err = json.Unmarshal(msg.Data, &summary)
	if err != nil {
		return nil, err
	}

	in.Response = &api.ScanSummaryResponse{
		Result: summary,
	}
	return obj, nil
}
