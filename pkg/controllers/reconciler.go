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
	cu "kmodules.xyz/client-go/client"
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

	if isr.Status.Phase == "" {
		if err := r.setDefaultStatus(isr); err != nil {
			return ctrl.Result{}, err
		}
	}

	err := r.scanForSingleImage(isr)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = r.doReportRelatedStuffs(isr)
	return ctrl.Result{}, err
}

func (r *Reconciler) setDefaultStatus(isr api.ImageScanRequest) error {
	_, _, err := cu.PatchStatus(r.ctx, r.Client, &isr, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Image = &api.ImageDetails{
			Name: isr.Spec.ImageRef,
		}
		in.Status.Phase = api.ImageScanRequestPhaseInProgress
		return in
	})
	return err
}

func (r *Reconciler) scanForSingleImage(isr api.ImageScanRequest) error {
	imageRef, err := name.ParseReference(isr.Spec.ImageRef)
	if err != nil {
		return err
	}

	isPrivate, err := backend.CheckPrivateImage(imageRef)
	if err != nil {
		klog.Errorf("Some serious error occurred when checking if the image is Private: %v \n", err)
		return err
	}

	err = r.updateImageDetails(isr, isPrivate)
	if err != nil {
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

func (r *Reconciler) updateImageDetails(isr api.ImageScanRequest, isPrivate bool) error {
	tag, dig, err := tagAndDigest(isr.Spec.ImageRef)
	if err != nil {
		return err
	}

	_, _, err = cu.PatchStatus(r.ctx, r.Client, &isr, func(obj client.Object) client.Object {
		in := obj.(*api.ImageScanRequest)
		in.Status.Image.Visibility = func() api.ImageVisibility {
			if isPrivate {
				return api.ImagePrivate
			}
			return api.ImagePublic
		}()
		in.Status.Image.Tag = tag
		in.Status.Image.Digest = dig
		return in
	})
	return err
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
		Complete(r)
}
