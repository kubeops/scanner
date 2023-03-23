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
	"time"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/nats-io/nats.go"
	batch "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
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

type RequestReconciler struct {
	*Reconciler
	req *api.ImageScanRequest
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
	var scanreq api.ImageScanRequest
	if err := r.Get(ctx, req.NamespacedName, &scanreq); err != nil {
		wlog.Error(err, "unable to fetch imageScanRequest object")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	rr := RequestReconciler{
		Reconciler: r,
		req:        &scanreq,
	}

	if !rr.isReconciliationNeeded() {
		return ctrl.Result{RequeueAfter: backend.TrivyRefreshPeriod}, nil
	}
	if scanreq.Status.JobName != "" { // Only for Private Images
		job, err := rr.getScannerJob()
		if err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		if rr.isRunning(job) && job.Status.Succeeded > 0 {
			return ctrl.Result{RequeueAfter: backend.TrivyRefreshPeriod}, rr.updateStatusWithReportDetails()
		}
	}

	if scanreq.Status.Phase == "" {
		if err := rr.setDefaultStatus(); err != nil {
			return ctrl.Result{}, err
		}
	}

	// We are here means, Phase is Pending or Outdated
	rc, err := rr.scan()
	if err != nil {
		return ctrl.Result{}, err
	}
	return returnAccordingToRequeueCode(rc), nil
}

func (r *RequestReconciler) isReconciliationNeeded() bool {
	report := r.req.Status.ReportRef
	if report == nil {
		return true
	}
	if time.Since(report.LastChecked.Time) > backend.TrivyRefreshPeriod {
		// report is older than 6 hours
		_ = r.updateStatusAsOutdated()
		return true
	}
	return false
}

func (r *RequestReconciler) getScannerJob() (*batch.Job, error) {
	var job batch.Job
	err := r.Get(r.ctx, types.NamespacedName{
		Name:      r.req.Status.JobName,
		Namespace: r.req.Spec.Namespace,
	}, &job)
	if err != nil {
		klog.Errorf("error %v on getting %v/%v job \n", err, r.req.Spec.Namespace, r.req.Status.JobName)
		return nil, err
	}
	return &job, nil
}

func (r *RequestReconciler) isRunning(job *batch.Job) bool {
	if r.req.Status.ReportRef == nil {
		return true
	}
	if job == nil {
		return false
	}
	if r.req.Status.Phase == api.ImageScanRequestPhaseOutdated && time.Since(job.CreationTimestamp.Time) < time.Minute*10 {
		return true
	}
	return false
}

func (r *RequestReconciler) scan() (requeueCode, error) {
	resp, err := backend.GetResponseFromBackend(r.nc, r.req.Spec.Image)
	if err != nil {
		return requeueCodeNone, err
	}
	if resp.Visibility == trivy.ImageVisibilityUnknown {
		klog.Infof("visibility of %s image is unknown \n", r.req.Spec.Image)
		return requeueCodeNone, nil
	}

	err = r.updateStatusWithImageDetails(resp.Visibility)
	if err != nil {
		return requeueCodeNone, err
	}

	if resp.Visibility == trivy.ImageVisibilityPrivate {
		return requeueCodeNone, r.ScanForPrivateImage()
	}

	// if the report is not generated yet (just submitted for scanning)
	if resp.Report.ArtifactName == "" { // `ArtifactName` is just a random field to check whether the report generated
		return requeueCodeFaster, nil
	}

	// Report related stuffs for private image will be done by `scanner upload-report` command in job's container.
	rep, err := EnsureScanReport(r.Client, r.req.Spec.Image, resp)
	if err != nil {
		return requeueCodeNone, err
	}
	return requeueCodeDelay, r.updateStatusAsReportEnsured(rep)
}

func returnAccordingToRequeueCode(rc requeueCode) ctrl.Result {
	if rc == requeueCodeFaster {
		return ctrl.Result{RequeueAfter: time.Minute}
	}
	if rc == requeueCodeDelay {
		return ctrl.Result{RequeueAfter: backend.TrivyRefreshPeriod}
	}
	return ctrl.Result{}
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.ImageScanRequest{}).
		Owns(&batch.Job{}).
		Complete(r)
}
