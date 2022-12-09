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

package scanner

import (
	"context"

	api "kubeops.dev/scanner/apis/cves/v1alpha1"
	"kubeops.dev/scanner/client/clientset/versioned"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/nats-io/nats.go"
	apps "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"kmodules.xyz/client-go/client/duck"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// WorkloadReconciler reconciles a Workload object
type WorkloadReconciler struct {
	client.Client
	nc           *nats.Conn
	client_set   *versioned.Clientset
	scannerImage string
}

var _ duck.Reconciler = &WorkloadReconciler{}

func NewWorkloadReconciler(nc *nats.Conn, client_set *versioned.Clientset, scannedImage string) *WorkloadReconciler {
	return &WorkloadReconciler{
		nc:           nc,
		client_set:   client_set,
		scannerImage: scannedImage,
	}
}

func (r *WorkloadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

func (r *WorkloadReconciler) calcForSinglePod(pod *core.Pod) ([]string, error) {
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

func (r *WorkloadReconciler) scanForSingleImage(ref string, extraInfo ImageMeta) error {
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
	_, err := r.client_set.CvesV1alpha1().ImageScanRequests().Create(context.TODO(), &isreq, metav1.CreateOptions{})
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

func (r *WorkloadReconciler) InjectClient(c client.Client) error {
	r.Client = c
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return duck.ControllerManagedBy(mgr).
		For(&api.Workload{}).
		WithUnderlyingTypes(
			core.SchemeGroupVersion.WithKind("ReplicationController"),
			apps.SchemeGroupVersion.WithKind("Deployment"),
			apps.SchemeGroupVersion.WithKind("StatefulSet"),
			apps.SchemeGroupVersion.WithKind("DaemonSet"),
			batch.SchemeGroupVersion.WithKind("Job"),
			batch.SchemeGroupVersion.WithKind("CronJob"),
		).
		Complete(func() duck.Reconciler {
			wr := new(WorkloadReconciler)
			wr.nc = r.nc
			wr.scannerImage = r.scannerImage
			wr.client_set = r.client_set
			return wr
		})
}
