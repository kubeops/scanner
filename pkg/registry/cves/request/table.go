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
	"fmt"
	"net/http"
	"time"

	"kubeops.dev/scanner/apis/cves/v1alpha1"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/duration"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
)

/*
Adapted from:
  - https://github.com/kubernetes/apiserver/blob/master/pkg/registry/rest/table.go
  - https://github.com/kubernetes/kubernetes/blob/v1.25.0/pkg/printers/internalversion/printers.go#L190-L198
*/

type defaultTableConvertor struct {
	defaultQualifiedResource schema.GroupResource
}

// NewTableConvertor creates a default convertor; the provided resource is used for error messages
// if no resource info can be determined from the context passed to ConvertToTable.
func NewTableConvertor(defaultQualifiedResource schema.GroupResource) rest.TableConvertor {
	return defaultTableConvertor{defaultQualifiedResource: defaultQualifiedResource}
}

var swaggerMetadataDescriptions = metav1.ObjectMeta{}.SwaggerDoc()

func (c defaultTableConvertor) ConvertToTable(ctx context.Context, object runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	var table metav1.Table
	fn := func(obj runtime.Object) error {
		var (
			image      string
			reportName string
			status     string
		)
		if o, ok := obj.(*v1alpha1.ImageScanRequest); ok {
			if o.Status.Image != nil {
				if o.Status.Image.Digest != "" {
					image = o.Status.Image.Image + "@" + o.Status.Image.Digest
				} else if o.Status.Image.Tag != "" {
					image = o.Status.Image.Image + ":" + o.Status.Image.Tag
				} else {
					image = o.Status.Image.Image
				}
			}
			if o.Status.ReportRef != nil {
				reportName = o.Status.ReportRef.Name
			}
			status = o.Status.Phase
		}

		m, err := meta.Accessor(obj)
		if err != nil {
			resource := c.defaultQualifiedResource
			if info, ok := genericapirequest.RequestInfoFrom(ctx); ok {
				resource = schema.GroupResource{Group: info.APIGroup, Resource: info.Resource}
			}
			return errNotAcceptable{resource: resource}
		}

		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				m.GetName(),
				image,
				reportName,
				status,
			},
			Object: runtime.RawExtension{Object: obj},
		})
		return nil
	}
	switch {
	case meta.IsListType(object):
		if err := meta.EachListItem(object, fn); err != nil {
			return nil, err
		}
	default:
		if err := fn(object); err != nil {
			return nil, err
		}
	}
	if m, err := meta.ListAccessor(object); err == nil {
		table.ResourceVersion = m.GetResourceVersion()
		table.Continue = m.GetContinue()
		table.RemainingItemCount = m.GetRemainingItemCount()
	} else {
		if m, err := meta.CommonAccessor(object); err == nil {
			table.ResourceVersion = m.GetResourceVersion()
		}
	}
	if opt, ok := tableOptions.(*metav1.TableOptions); !ok || !opt.NoHeaders {
		table.ColumnDefinitions = []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name", Description: swaggerMetadataDescriptions["name"]},
			{Name: "Image", Type: "string", Description: ""},
			{Name: "Report Name", Type: "string", Description: ""},
			{Name: "Status", Type: "string", Description: ""},
		}
	}
	return &table, nil
}

// errNotAcceptable indicates the resource doesn't support Table conversion
type errNotAcceptable struct {
	resource schema.GroupResource
}

func (e errNotAcceptable) Error() string {
	return fmt.Sprintf("the resource %s does not support being converted to a Table", e.resource)
}

func (e errNotAcceptable) Status() metav1.Status {
	return metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusNotAcceptable,
		Reason:  metav1.StatusReason("NotAcceptable"),
		Message: e.Error(),
	}
}

// convertToHumanReadableDateType returns the elapsed time since timestamp in
// human-readable approximation.
// ref: https://github.com/kubernetes/apimachinery/blob/v0.21.1/pkg/api/meta/table/table.go#L63-L70
// But works for timestamp before or after now.
func convertToHumanReadableDateType(timestamp time.Time) string {
	if timestamp.IsZero() {
		return "<unknown>"
	}
	var d time.Duration
	now := time.Now()
	if now.After(timestamp) {
		d = now.Sub(timestamp)
	} else {
		d = timestamp.Sub(now)
	}
	return duration.HumanDuration(d)
}
