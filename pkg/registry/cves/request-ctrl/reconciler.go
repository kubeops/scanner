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

package request_ctrl

import (
	"context"

	api "kubeops.dev/scanner/apis/cves/v1alpha1"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/nats-io/nats.go"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"kmodules.xyz/client-go/client/duck"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconciler reconciles a Workload object
type Reconciler struct {
	client.Client
	nc           *nats.Conn
	scannerImage string
}

var _ duck.Reconciler = &Reconciler{}

func NewImaeScanRequestReconciler(nc *nats.Conn, scannedImage string) *Reconciler {
	return &Reconciler{
		nc:           nc,
		scannerImage: scannedImage,
	}
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	wlog := log.FromContext(ctx)

	wlog.Info("Reconciling for ", "req", req)
	var wl api.Workload
	if err := r.Get(ctx, req.NamespacedName, &wl); err != nil {
		wlog.Error(err, "unable to fetch Workload")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	err := backend.EnsureCronJobToRefreshTrivyDB(r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	sel, err := metav1.LabelSelectorAsSelector(wl.Spec.Selector)
	if err != nil {
		return ctrl.Result{}, err
	}

	var pods core.PodList
	err = r.List(context.TODO(), &pods,
		client.InNamespace(wl.Namespace),
		client.MatchingLabelsSelector{Selector: sel})
	if err != nil {
		return ctrl.Result{}, err
	}

	lookup := make(map[string]ImageMeta, 0)
	for _, pod := range pods.Items {
		imgToInsert, err := r.calcForSinglePod(&pod)
		if err != nil {
			return ctrl.Result{}, err
		}
		for i := 0; i < len(imgToInsert); i++ {
			lookup[imgToInsert[i]] = ImageMeta{
				Namespace:        pod.Namespace,
				ImagePullSecrets: pod.Spec.ImagePullSecrets,
			}
		}
	}

	for key, value := range lookup {
		if err = r.scanForSingleImage(key, value); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) calcForSinglePod(pod *core.Pod) ([]string, error) {
	fnRef := func(c core.ContainerStatus) (string, error) {
		imageRef, err := name.ParseReference(c.Image)
		if err != nil {
			return "", err
		}
		imageIDRef, err := name.ParseReference(c.ImageID)
		if err != nil {
			return "", err
		}
		if imageRef.Context() != imageIDRef.Context() {
			return c.Image, nil
		}
		return c.ImageID, nil
	}
	toInsert := make([]string, 0)
	for _, c := range pod.Status.ContainerStatuses {
		ref, err := fnRef(c)
		if err != nil {
			return toInsert, err
		}
		toInsert = append(toInsert, ref)
	}
	for _, c := range pod.Status.InitContainerStatuses {
		ref, err := fnRef(c)
		if err != nil {
			return toInsert, err
		}
		toInsert = append(toInsert, ref)
	}
	for _, c := range pod.Status.EphemeralContainerStatuses {
		ref, err := fnRef(c)
		if err != nil {
			return toInsert, err
		}
		toInsert = append(toInsert, ref)
	}
	return toInsert, nil
}

func (r *Reconciler) scanForSingleImage(ref string, extraInfo ImageMeta) error {
	isreq := api.ImageScanRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.ResourceKindImageScanRequest,
			APIVersion: api.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "scanreq-", // TODO: use image name
		},
		Spec: api.ImageScanRequestSpec{
			ImageRef:    ref,
			PullSecrets: extraInfo.ImagePullSecrets,
			Namespace:   extraInfo.Namespace,
		},
	}

	// API call to handle all the other things from ui-server repo
	err := r.Client.Create(context.TODO(), &isreq, &client.CreateOptions{})
	if err != nil {
		return err
	}

	imageRef, err := name.ParseReference(ref)
	if err != nil {
		return err
	}

	isPrivate, err := backend.CheckPrivateImage(imageRef)
	if err != nil {
		klog.Errorf("Its not a simple unauthorized error. Some serious error occurred: %v \n", err)
		return err
	}
	info := NewImageInfo(ref, extraInfo)

	if isPrivate {
		return r.ScanForPrivateImage(info)
	}
	// Call SubmitScanRequest only for public image
	err = backend.SubmitScanRequest(r.nc, "scanner.queue.scan", info.Image)
	if err != nil {
		klog.Errorf("error on Submitting ScanRequest ", err)
	}
	return err
}

func (r *Reconciler) InjectClient(c client.Client) error {
	r.Client = c
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.ImageScanRequest{}).
		Complete(r)
}
