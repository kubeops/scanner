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
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Reconciler struct {
	client.Client
	nc                      *nats.Conn
	scannerImage            string
	trivyImage              string
	trivyDBCacherImage      string
	fileServerAddr          string
	fileServerDir           string
	garbageCollectionPeriod time.Duration
}

type RequestReconciler struct {
	*Reconciler
	ctx context.Context
	req *api.ImageScanRequest
}

func NewImageScanRequestReconciler(
	kc client.Client,
	nc *nats.Conn,
	scannedImage, trivyImage, trivyDBCacherImage, fsAddr, fsDir string,
	garbageCol time.Duration,
) *Reconciler {
	return &Reconciler{
		Client:                  kc,
		nc:                      nc,
		scannerImage:            scannedImage,
		trivyImage:              trivyImage,
		trivyDBCacherImage:      trivyDBCacherImage,
		fileServerAddr:          fsAddr,
		fileServerDir:           fsDir,
		garbageCollectionPeriod: garbageCol,
	}
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("Reconciling for ", "req", req)
	var scanreq api.ImageScanRequest
	if err := r.Get(ctx, req.NamespacedName, &scanreq); err != nil {
		log.Error(err, "unable to fetch imageScanRequest object")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	rr := RequestReconciler{
		Reconciler: r,
		ctx:        ctx,
		req:        &scanreq,
	}

	if scanreq.Complete() &&
		time.Since(scanreq.CreationTimestamp.Time) > r.garbageCollectionPeriod {
		return ctrl.Result{}, r.Delete(ctx, &scanreq)
	}

	if needed, err := rr.isReconciliationNeeded(); err != nil || !needed {
		return ctrl.Result{}, err
	}

	if scanreq.Status.JobName != "" { // Only for Private Images
		cont, err := rr.doStuffsForPrivateImage()
		if err != nil || !cont {
			return ctrl.Result{}, err
		}
	}

	if scanreq.Status.Phase == "" {
		if err := rr.setDefaultStatus(); err != nil {
			return ctrl.Result{}, err
		}
	}

	// We are here means, Phase is Pending or Outdated
	return rr.scan()
}

func (r *RequestReconciler) isReconciliationNeeded() (bool, error) {
	report := r.req.Status.ReportRef
	if report == nil {
		return true, nil
	}

	isrp, err := getReport(r.Client, report.Name)
	if err != nil {
		return true, err
	} else if isrp == nil {
		return true, nil
	}

	ver, err := readFromFileServer(r.fileServerDir)
	if err != nil {
		return true, err
	}

	if isrp.Status.Version.VulnerabilityDB.UpdatedAt.Time.Sub(ver.UpdatedAt.Time) > backend.TrivyRefreshPeriod {
		_ = r.updateStatusAsOutdated()
		return true, nil
	}
	return false, nil
}

func (r *RequestReconciler) doStuffsForPrivateImage() (bool, error) {
	job, err := r.getPrivateImageScannerJob()
	if err != nil && !errors.IsNotFound(err) {
		return false, err
	}

	if job != nil {
		digest, err := r.getDigestForPrivateImage(job)
		if err != nil {
			return false, err
		}

		err = r.ensureDigestInRequestAndReport(digest)
		if err != nil {
			return false, err
		}
	}

	if job != nil && job.Status.Succeeded > 0 { // job succeeded
		return false, r.updateStatusWithReportDetails()
	}
	return true, nil // true means, we need to continue
}

func (r *RequestReconciler) scan() (ctrl.Result, error) {
	resp, err := backend.GetResponseFromBackend(r.nc, r.req.Spec.Image)
	if err != nil {
		return ctrl.Result{}, err
	}
	if resp.ImageDetails.Visibility == trivy.ImageVisibilityUnknown {
		klog.Infof("visibility of %s image is unknown \n", r.req.Spec.Image)
		return ctrl.Result{}, nil
	}

	err = r.updateStatusWithImageDetails(resp.ImageDetails.Visibility)
	if err != nil {
		return ctrl.Result{}, err
	}

	if resp.ImageDetails.Visibility == trivy.ImageVisibilityPrivate {
		return ctrl.Result{}, r.ScanForPrivateImage()
	}

	// if the report is not generated yet (just submitted for scanning)
	if resp.Report.ArtifactName == "" { // `ArtifactName` is just a random field to check whether the report generated
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Report related stuffs for private image will be done by `scanner upload-report` command in job's container.
	rep, err := EnsureScanReport(r.Client, r.req.Spec.Image, resp)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.updateStatusAsReportEnsured(rep)
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.ImageScanRequest{}).
		Owns(&batch.Job{}).
		Complete(r)
}
