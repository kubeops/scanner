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

package controllers

import (
	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"

	"k8s.io/apimachinery/pkg/types"
	kutil "kmodules.xyz/client-go"
	cu "kmodules.xyz/client-go/client"
	kname "kmodules.xyz/go-containerregistry/name"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *RequestReconciler) setDefaultStatus() error {
	_, _, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Image = &api.ImageDetails{
			Name: r.req.Spec.Image,
		}
		in.Status.Phase = api.ImageScanRequestPhasePending
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusWithImageDetails(vis trivy.ImageVisibility) error {
	tag, dig, err := tagAndDigest(r.req.Spec.Image)
	if err != nil {
		return err
	}

	_, _, err = cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Image.Visibility = vis
		in.Status.Image.Tag = tag
		in.Status.Image.Digest = dig
		in.Status.Phase = api.ImageScanRequestPhaseInProgress
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusWithJobName(jobName string, vt kutil.VerbType) error {
	_, _, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.JobName = jobName
		if vt == kutil.VerbCreated {
			// For Outdated private image, reportRef should explicitly be set to nil, to meet the `job is still running` case in Reconcile()
			in.Status.ReportRef = nil
		}
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusAsReportEnsured(rep *api.ImageScanReport) error {
	_, _, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.ReportRef = &api.ScanReportRef{
			Name:        rep.GetName(),
			LastChecked: rep.Status.LastChecked,
		}
		in.Status.Phase = api.ImageScanRequestPhaseCurrent
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusAsOutdated() error {
	_, _, err := cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Phase = api.ImageScanRequestPhaseOutdated
		return in
	})
	return err
}

func (r *RequestReconciler) updateStatusWithReportDetails() error {
	img, err := kname.ParseReference(r.req.Spec.Image)
	if err != nil {
		return err
	}

	var rep api.ImageScanReport
	err = r.Get(r.ctx, types.NamespacedName{
		Name: getReportName(img.Name),
	}, &rep)
	if err != nil {
		return err
	}

	_, _, err = cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.ReportRef = &api.ScanReportRef{
			Name:        getReportName(img.Name),
			LastChecked: rep.Status.LastChecked,
		}
		in.Status.Phase = api.ImageScanRequestPhaseCurrent
		return in
	})
	return err
}
