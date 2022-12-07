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

package scanner

import (
	"context"
	"errors"

	api "kubeops.dev/scanner/apis/cves/v1alpha1"

	"github.com/nats-io/nats.go"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type AppReport struct {
	cid  string
	nc   *nats.Conn
	kc   client.Client
	auth authorizer.Authorizer
	gr   schema.GroupResource
}

var (
	_ rest.GroupVersionKindProvider = &AppReport{}
	_ rest.Scoper                   = &AppReport{}
	_ rest.Getter                   = &AppReport{}
	_ rest.Storage                  = &AppReport{}
)

func NewAppReportStorage(cid string, nc *nats.Conn, kc client.Client, auth authorizer.Authorizer) *AppReport {
	s := &AppReport{
		cid:  cid,
		nc:   nc,
		kc:   kc,
		auth: auth,
	}
	return s
}

func (r *AppReport) GroupVersionKind(_ schema.GroupVersion) schema.GroupVersionKind {
	return api.SchemeGroupVersion.WithKind(api.ResourceKindScanSummary)
}

func (r *AppReport) NamespaceScoped() bool {
	return true
}

func (r *AppReport) New() runtime.Object {
	return &api.ScanSummary{}
}

func (r *AppReport) Destroy() {}

func (r *AppReport) Get(ctx context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	ns, ok := apirequest.NamespaceFrom(ctx)
	if !ok {
		return nil, apierrors.NewBadRequest("missing namespace")
	}

	user, ok := apirequest.UserFrom(ctx)
	if !ok {
		return nil, apierrors.NewBadRequest("missing user info")
	}

	attrs := authorizer.AttributesRecord{
		User:      user,
		Verb:      "get",
		Namespace: ns,
		APIGroup:  r.gr.Group,
		Resource:  r.gr.Resource,
		Name:      name,
	}
	decision, why, err := r.auth.Authorize(ctx, attrs)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if decision != authorizer.DecisionAllow {
		return nil, apierrors.NewForbidden(r.gr, name, errors.New(why))
	}

	panic("implement me")
}
