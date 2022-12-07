package imagescanreport

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
	cves "kubeops.dev/scanner/apis/cves/v1alpha1"
)

// NewStrategy creates and returns a fischerStrategy instance
func NewStrategy(typer runtime.ObjectTyper) fischerStrategy {
	return fischerStrategy{typer, names.SimpleNameGenerator}
}

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a ImageScanReport
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	apiserver, ok := obj.(*cves.ImageScanReport)
	if !ok {
		return nil, nil, fmt.Errorf("given object is not a ImageScanReport")
	}
	return labels.Set(apiserver.ObjectMeta.Labels), SelectableFields(apiserver), nil
}

// MatchImageScanReport is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchImageScanReport(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *cves.ImageScanReport) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type fischerStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

func (fischerStrategy) NamespaceScoped() bool {
	return false
}

func (fischerStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
}

func (fischerStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
}

func (fischerStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (fischerStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string { return nil }

func (fischerStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (fischerStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (fischerStrategy) Canonicalize(obj runtime.Object) {
}

func (fischerStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (fischerStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
