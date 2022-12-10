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
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/shared"
	"kubeops.dev/scanner/pkg/backend"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	kutil "kmodules.xyz/client-go"
	cu "kmodules.xyz/client-go/client"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *Reconciler) createImageScanReport(isr api.ImageScanRequest) error {
	msg, err := r.nc.Request("scanner.report", []byte(isr.Spec.ImageRef), backend.NatsRequestTimeout)
	if err != nil {
		return err
	}
	var report api.SingleReport
	err = json.Unmarshal(msg.Data, &report)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("%x", md5.Sum([]byte(isr.Spec.ImageRef)))
	tag, dig := getTagAndDigest(isr.Spec.ImageRef)

	obj, vt, err := cu.CreateOrPatch(r.ctx, r.Client, &api.ImageScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}, func(obj client.Object, createOp bool) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Spec.Image = isr.Spec.ImageRef
		rep.Spec.Tag = tag
		rep.Spec.Digest = dig
		return rep
	})
	if err != nil {
		return err
	}
	if vt == kutil.VerbCreated {
		klog.Infof("$v ImageScanReport has been created", obj.GetName())
	}

	// TODO: Is a single CreateOrPatch is able to modify the status too ?
	_, _, err = cu.PatchStatus(r.ctx, r.Client, &api.ImageScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}, func(obj client.Object) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Status.LastChecked = shared.Time(metav1.Time{Time: time.Now()})
		// TODO: we need to set the TruvyDB version too
		rep.Status.Report = report
		return rep
	})
	return err
}

func getTagAndDigest(img string) (string, string) {
	// TODO: is this ok ? Or Should we use `crane` pkg to do so ?
	imgWithoutHash := img
	hash := ""
	tag := ""
	if strings.Contains(img, "@") {
		slice := strings.Split(img, "@")
		imgWithoutHash = slice[0]
		hash = slice[1]
	}

	if strings.Contains(imgWithoutHash, ":") {
		slice := strings.Split(imgWithoutHash, ":")
		tag = slice[1]
	}
	return tag, hash
}
