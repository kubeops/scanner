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

package scanreport

import (
	"context"
	"time"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/pkg/fileserver"

	"k8s.io/apimachinery/pkg/runtime"
	cu "kmodules.xyz/client-go/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ImageScanReportReconciler reconciles a ImageScanReport object
type ImageScanReportReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	FileServerDir string
	ReportTTL     time.Duration
}

func (r *ImageScanReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var isrp api.ImageScanReport
	if err := r.Get(ctx, req.NamespacedName, &isrp); err != nil {
		log.Error(err, "unable to fetch ImageScanReport")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	status := isrp.Status.DeepCopy()

	dbTimestamp, err := fileserver.VulnerabilityDBLastUpdatedAt(r.FileServerDir)
	if err != nil {
		return ctrl.Result{}, err
	}

	if dbTimestamp.After(isrp.Status.Version.VulnerabilityDB.UpdatedAt.Time) {
		status.Phase = api.ImageScanReportPhaseOutdated
		later := isrp.CreationTimestamp.Time
		if isrp.CreationTimestamp.Time.Before(isrp.Status.Version.VulnerabilityDB.UpdatedAt.Time) {
			later = isrp.Status.Version.VulnerabilityDB.UpdatedAt.Time
		}
		if time.Since(later) >= r.ReportTTL {
			return ctrl.Result{}, r.Delete(ctx, &isrp)
		}
	} else {
		status.Phase = api.ImageScanReportPhaseCurrent
	}

	_, _, err = cu.PatchStatus(ctx, r.Client, &isrp, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanReport)
		in.Status = *status
		return in
	})
	return ctrl.Result{}, client.IgnoreNotFound(err)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageScanReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.ImageScanReport{}).
		Complete(r)
}
