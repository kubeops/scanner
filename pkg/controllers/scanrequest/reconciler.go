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
	"time"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/nats-io/nats.go"
	batch "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"kmodules.xyz/go-containerregistry/name"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type Reconciler struct {
	client.Client
	nc                   *nats.Conn
	scannerImage         string
	trivyImage           string
	trivyDBCacherImage   string
	fileServerAddr       string
	scanRequestTTLPeriod time.Duration
	workspace            string
}

type RequestReconciler struct {
	*Reconciler
	ctx context.Context
	req *api.ImageScanRequest
}

func NewImageScanRequestReconciler(
	kc client.Client,
	nc *nats.Conn,
	scannedImage, trivyImage, trivyDBCacherImage, fsAddr string,
	garbageCol time.Duration,
	workspace string,
) *Reconciler {
	return &Reconciler{
		Client:               kc,
		nc:                   nc,
		scannerImage:         scannedImage,
		trivyImage:           trivyImage,
		trivyDBCacherImage:   trivyDBCacherImage,
		fileServerAddr:       fsAddr,
		scanRequestTTLPeriod: garbageCol,
		workspace:            workspace,
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

	if scanreq.IsComplete() {
		if time.Since(scanreq.CreationTimestamp.Time) >= r.scanRequestTTLPeriod {
			return ctrl.Result{}, r.Delete(ctx, &scanreq)
		} else {
			// We don't want to reconcile, after the ImageScanRequest is Completed
			return ctrl.Result{}, nil
		}
	}

	if scanreq.Status.JobName != "" { // Only for Private Images
		// as the job has already been created, & phase is not Current/Outdated yet,
		// So, we are here to ensure digest, update report details & request's Phase;  Not for scanning
		return ctrl.Result{}, rr.doStuffsForPrivateImage()
	}

	if needed, err := rr.freshScanRequired(); err != nil || !needed {
		return ctrl.Result{}, err
	}

	if scanreq.Status.Phase == "" {
		if err := rr.setDefaultStatus(); err != nil {
			return ctrl.Result{}, err
		}
	}

	// We are here means, Phase is Pending or InProgress
	return rr.scan()
}

func (r *RequestReconciler) freshScanRequired() (bool, error) {
	reportName, err := func() (string, error) {
		if r.req.Status.ReportRef != nil {
			return r.req.Status.ReportRef.Name, nil
		}
		var ref *name.Image
		ref, err := name.ParseReference(r.req.Spec.Image)
		if err != nil {
			return "", err
		}
		return api.GetReportName(ref.Name), nil
	}()
	if err != nil {
		return true, err
	}
	var isrp api.ImageScanReport
	err = r.Get(r.ctx, types.NamespacedName{Name: reportName}, &isrp)
	if err != nil {
		return true, client.IgnoreNotFound(err)
	}
	if isrp.Status.Phase == api.ImageScanReportPhaseOutdated {
		return true, nil
	}
	return false, r.updateStatusAsReportAlreadyExists(&isrp)
}

func (r *RequestReconciler) doStuffsForPrivateImage() error {
	job, err := r.getPrivateImageScannerJob()
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	pod, err := r.getPrivateImageScannerPod(job)
	if err != nil || pod == nil {
		return err
	}

	digest, err := r.getDigestForPrivateImage(pod)
	if err != nil {
		return err
	}

	err = r.ensureDigestInRequestAndReport(digest)
	if err != nil {
		return err
	}

	if job.Status.Succeeded > 0 {
		return r.updateStatusWithReportDetails()
	}
	if job.Status.Failed > 0 {
		return r.updateStatusAsFailed(pod.Status.Message)
	}
	return nil
}

func (r *RequestReconciler) scan() (ctrl.Result, error) {
	resp, err := backend.GetResponseFromBackend(r.nc, r.req.Spec.Image)
	if err != nil {
		return ctrl.Result{}, err
	}
	if resp.ImageDetails.Visibility == trivy.ImageVisibilityUnknown {
		klog.Infof("visibility of %s image is unknown \n", r.req.Spec.Image)
		return ctrl.Result{}, r.updateStatusAsFailed(resp.ErrorMessage)
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
		Watches(&source.Kind{Type: &batch.Job{}}, handler.EnqueueRequestsFromMapFunc(r.watcherFuncForJob())).
		Complete(r)
}

func (r *Reconciler) watcherFuncForJob() handler.MapFunc {
	return func(object client.Object) []reconcile.Request {
		job := object.(*batch.Job)
		var scanReqs api.ImageScanRequestList
		var reqs []reconcile.Request

		if job.Namespace != r.workspace {
			return reqs
		}

		err := r.Client.List(context.TODO(), &scanReqs, &client.ListOptions{})
		if err != nil {
			return reqs
		}
		for _, s := range scanReqs.Items {
			if s.Status.JobName == job.Name {
				// Yes , We have got the required Job object, so this scanReq should be requeue
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      s.Name,
						Namespace: s.Namespace,
					},
				})
			}
		}
		return reqs
	}
}
