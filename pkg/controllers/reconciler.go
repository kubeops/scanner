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
	"time"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/nats-io/nats.go"
	batch "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	cu "kmodules.xyz/client-go/client"
	kname "kmodules.xyz/go-containerregistry/name"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Reconciler struct {
	client.Client
	ctx                context.Context
	nc                 *nats.Conn
	scannerImage       string
	trivyImage         string
	trivyDBCacherImage string
	fileServerAddr     string
}

func NewImageScanRequestReconciler(kc client.Client, nc *nats.Conn, scannedImage, trivyImage, trivyDBCacherImage, fsAddr string) *Reconciler {
	return &Reconciler{
		Client:             kc,
		nc:                 nc,
		scannerImage:       scannedImage,
		trivyImage:         trivyImage,
		trivyDBCacherImage: trivyDBCacherImage,
		fileServerAddr:     fsAddr,
	}
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.ctx = ctx
	wlog := log.FromContext(ctx)

	wlog.Info("Reconciling for ", "req", req)
	var isr api.ImageScanRequest
	if err := r.Get(ctx, req.NamespacedName, &isr); err != nil {
		wlog.Error(err, "unable to fetch imageScanRequest object")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !r.isReconciliationNeeded(isr) {
		return ctrl.Result{}, nil
	}
	if isr.Status.ReportRef == nil && isr.Status.JobName != "" {
		// For Private Images, Job is still running case.
		if r.isJobSucceeded(isr) {
			return ctrl.Result{}, r.patchReportRefAndPhase(isr)
		}
	}

	if isr.Status.Phase == "" {
		if err := r.setDefaultStatus(isr); err != nil {
			return ctrl.Result{}, err
		}
	}

	// We are here means, Phase is Pending or Outdated
	return ctrl.Result{}, r.scan(isr)
}

func (r *Reconciler) isReconciliationNeeded(isr api.ImageScanRequest) bool {
	rep := isr.Status.ReportRef
	if rep == nil {
		return true
	}
	if rep != nil && time.Since(rep.LastChecked.Time) > time.Hour*6 {
		// report is older than 6 hours
		_ = r.updateStatusAsOutdated(isr)
		return true
	}
	return false
}

func (r *Reconciler) isJobSucceeded(isr api.ImageScanRequest) bool {
	var job batch.Job
	err := r.Get(r.ctx, types.NamespacedName{
		Name:      isr.Status.JobName,
		Namespace: isr.Spec.Namespace,
	}, &job)
	if err != nil {
		klog.Errorf("error %v on getting %v/%v job \n", err, isr.Spec.Namespace, isr.Status.JobName)
		return false
	}
	return job.Status.Succeeded > 0
}

func (r *Reconciler) patchReportRefAndPhase(isr api.ImageScanRequest) error {
	img, err := kname.ParseReference(isr.Spec.Image)
	if err != nil {
		return err
	}

	reportName := fmt.Sprintf("%x", md5.Sum([]byte(img.Name)))
	var rep api.ImageScanReport
	err = r.Get(r.ctx, types.NamespacedName{
		Name: reportName,
	}, &rep)
	if err != nil {
		return err
	}

	_, _, err = cu.PatchStatus(r.ctx, r.Client, &isr, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.ReportRef = &api.ScanReportRef{
			Name:        reportName,
			LastChecked: trivy.Time(rep.ObjectMeta.CreationTimestamp),
		}
		in.Status.Phase = api.ImageScanRequestPhaseCurrent
		return in
	})
	return err
}

func (r *Reconciler) scan(isr api.ImageScanRequest) error {
	resp, err := backend.PassToBackend(r.nc, isr.Spec.Image)
	if err != nil {
		return err
	}
	if resp.Visibility == trivy.BackendVisibilityUnknown {
		klog.Infof("visibility of %s image is unknown", isr.Spec.Image)
		return nil
	}

	err = r.updateStatusWithImageDetails(isr, resp.Visibility)
	if err != nil {
		return err
	}

	if resp.Visibility == trivy.BackendVisibilityPrivate {
		return r.ScanForPrivateImage(isr)
	}

	// Report related stuffs for private image will be done by `scanner upload-report` command in job's container.
	return r.doReportRelatedStuffs(isr)
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

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.ImageScanRequest{}).
		Owns(&batch.Job{}).
		Complete(r)
}
