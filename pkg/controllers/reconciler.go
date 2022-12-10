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

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/nats-io/nats.go"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Reconciler struct {
	client.Client
	ctx          context.Context
	nc           *nats.Conn
	scannerImage string
}

func NewImageScanRequestReconciler(kc client.Client, nc *nats.Conn, scannedImage string) *Reconciler {
	return &Reconciler{
		Client:       kc,
		nc:           nc,
		scannerImage: scannedImage,
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

	err := backend.EnsureCronJobToRefreshTrivyDB(r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = r.scanForSingleImage(isr)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = r.createImageScanReport(isr)
	return ctrl.Result{}, err
}

func (r *Reconciler) scanForSingleImage(isr api.ImageScanRequest) error {
	imageRef, err := name.ParseReference(isr.Spec.ImageRef)
	if err != nil {
		return err
	}

	isPrivate, err := backend.CheckPrivateImage(imageRef)
	if err != nil {
		klog.Errorf("Its not a simple unauthorized error. Some serious error occurred: %v \n", err)
		return err
	}

	if isPrivate {
		return r.ScanForPrivateImage(isr)
	}
	// Call SubmitScanRequest only for public image
	err = backend.SubmitScanRequest(r.nc, "scanner.queue.scan", isr.Spec.ImageRef)
	if err != nil {
		klog.Errorf("error on Submitting ScanRequest ", err)
	}
	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.ImageScanRequest{}).
		Complete(r)
}
