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
	"context"
	"crypto/md5"
	"fmt"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"

	"github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	kutil "kmodules.xyz/client-go"
	cu "kmodules.xyz/client-go/client"
	kname "kmodules.xyz/go-containerregistry/name"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func EnsureScanReport(kc client.Client, imageRef string, resp trivy.BackendResponse) (*api.ImageScanReport, error) {
	img, err := kname.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	obj, vt, err := cu.CreateOrPatch(context.TODO(), kc, &api.ImageScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: getReportName(img.Name),
		},
	}, func(obj client.Object, createOp bool) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Spec.Image = api.ImageReference{
			Name:   img.Name,
			Tag:    img.Tag,
			Digest: img.Digest,
		}
		return rep
	})
	if err != nil {
		return nil, err
	}
	if vt == kutil.VerbCreated {
		klog.Infof("%v ImageScanReport has been created\n", obj.GetName())
	}

	// TODO: Is a single CreateOrPatch is able to modify the status too ?
	_, _, err = cu.PatchStatus(context.TODO(), kc, &api.ImageScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: getReportName(img.Name),
		},
	}, func(obj client.Object) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Status.LastChecked = resp.LastModificationTime
		rep.Status.TrivyDBVersion = resp.TrivyVersion.Version
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

	return obj.(*api.ImageScanReport), nil
}

func upsertCVEs(kc client.Client, r trivy.SingleReport) error {
	vuls := map[string]trivy.Vulnerability{}

	for _, rpt := range r.Results {
		for _, tv := range rpt.Vulnerabilities {
			vuls[tv.VulnerabilityID] = tv
		}
	}

	for _, vul := range vuls {
		_, vt, err := cu.CreateOrPatch(context.TODO(), kc, &api.Vulnerability{
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

func getReportName(imgName string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(imgName)))
}

func tagAndDigest(img string) (string, string, error) {
	var (
		tag name.Tag
		dig name.Digest
		err error
	)
	tag, err = name.NewTag(img)
	if err != nil {
		dig, err = name.NewDigest(img)
		if err != nil {
			return "", "", err
		}
	}
	return tag.TagStr(), dig.DigestStr(), nil
}
