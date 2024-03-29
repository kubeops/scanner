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

package scanrequest

import (
	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"

	"k8s.io/apimachinery/pkg/types"
	cu "kmodules.xyz/client-go/client"
	"kmodules.xyz/go-containerregistry/name"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *RequestReconciler) setDefaultStatus() error {
	_, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Image = &trivy.ImageDetails{
			Name: r.req.Spec.Image,
		}
		in.Status.Phase = api.ImageScanRequestPhasePending
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusWithImageDetails(vis trivy.ImageVisibility) error {
	img, err := name.ParseReference(r.req.Spec.Image)
	if err != nil {
		return err
	}

	_, err = cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		if in.Status.Image == nil {
			in.Status.Image = new(trivy.ImageDetails)
		}
		in.Status.Image.Visibility = vis
		in.Status.Image.Name = img.Name
		in.Status.Image.Tag = img.Tag
		in.Status.Image.Digest = img.Digest
		in.Status.Phase = api.ImageScanRequestPhaseInProgress
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusWithJobName(jobName string) error {
	_, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.JobName = jobName
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusAsReportEnsured(rep *api.ImageScanReport) error {
	_, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		if in.Status.Image.Digest == "" {
			in.Status.Image.Digest = rep.Spec.Image.Digest
		}
		in.Status.ReportRef = &api.ScanReportRef{
			Name: rep.GetName(),
		}
		in.Status.Phase = api.ImageScanRequestPhaseCurrent
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusAsReportAlreadyExists(isrp *api.ImageScanReport) error {
	_, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.ReportRef = &api.ScanReportRef{
			Name: isrp.Name,
		}
		in.Status.Image = &trivy.ImageDetails{
			Name:       isrp.Spec.Image.Name,
			Tag:        isrp.Spec.Image.Tag,
			Digest:     isrp.Spec.Image.Digest,
			Visibility: trivy.ImageVisibilityUnknown, // existing report, so we don't know visibility
		}
		in.Status.Phase = api.ImageScanRequestPhaseCurrent
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusAsFailed(msg string) error {
	_, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Phase = api.ImageScanRequestPhaseFailed
		in.Status.Reason = msg
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusWithReportDetails() error {
	img, err := name.ParseReference(r.req.Spec.Image)
	if err != nil {
		return err
	}

	var rep api.ImageScanReport
	err = r.Get(r.ctx, types.NamespacedName{
		Name: api.GetReportName(img.Name),
	}, &rep)
	if err != nil {
		return err
	}

	_, err = cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.ReportRef = &api.ScanReportRef{
			Name: rep.Name,
		}
		in.Status.Phase = api.ImageScanRequestPhaseCurrent
		return in
	})
	return err
}
