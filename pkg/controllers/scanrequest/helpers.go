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
	"context"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	kutil "kmodules.xyz/client-go"
	cu "kmodules.xyz/client-go/client"
	"kmodules.xyz/go-containerregistry/name"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func EnsureScanReport(kc client.Client, imageRef string, resp trivy.BackendResponse) (*api.ImageScanReport, error) {
	img, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	obj := &api.ImageScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: api.GetReportName(img.Name),
		},
	}
	vt, err := cu.CreateOrPatch(context.TODO(), kc, obj, func(obj client.Object, createOp bool) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Spec.Image = api.ImageReference{
			Name:   resp.ImageDetails.Name,
			Tag:    resp.ImageDetails.Tag,
			Digest: resp.ImageDetails.Digest,
		}
		return rep
	})
	if err != nil {
		return nil, err
	}
	if vt == kutil.VerbCreated {
		klog.Infof("%v ImageScanReport has been created\n", obj.GetName())
	}

	_, err = cu.PatchStatus(context.TODO(), kc, obj, func(obj client.Object) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Status.Version = resp.TrivyVersion
		rep.Status.Report = resp.Report
		return rep
	})
	if err != nil {
		return nil, err
	}

	err = upsertCVEs(kc, resp.Report)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func upsertCVEs(kc client.Client, r trivy.SingleReport) error {
	vuls := map[string]trivy.Vulnerability{}

	for _, rpt := range r.Results {
		for _, tv := range rpt.Vulnerabilities {
			vuls[tv.VulnerabilityID] = tv
		}
	}

	for _, vul := range vuls {
		vt, err := cu.CreateOrPatch(context.TODO(), kc, &api.Vulnerability{
			ObjectMeta: metav1.ObjectMeta{
				Name: vul.VulnerabilityID,
			},
		}, func(o client.Object, createOp bool) client.Object {
			obj := o.(*api.Vulnerability)
			obj.Spec.Vulnerability = vul
			return obj
		})
		if err != nil {
			return err
		}
		klog.Infof("Vulnerability %s has been %s\n", vul.VulnerabilityID, vt)
	}
	return nil
}
