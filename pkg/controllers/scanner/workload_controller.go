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

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/pkg/backend"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/nats-io/nats.go"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"kmodules.xyz/client-go/client/duck"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// WorkloadReconciler reconciles a Workload object
type WorkloadReconciler struct {
	client.Client
	nc *nats.Conn
}

var _ duck.Reconciler = &WorkloadReconciler{}

func NewWorkloadReconciler(nc *nats.Conn) *WorkloadReconciler {
	return &WorkloadReconciler{
		nc: nc,
	}
}

func (r *WorkloadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var mypod api.Workload
	if err := r.Get(ctx, req.NamespacedName, &mypod); err != nil {
		log.Error(err, "unable to fetch Workload")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	sel, err := metav1.LabelSelectorAsSelector(mypod.Spec.Selector)
	if err != nil {
		return ctrl.Result{}, err
	}

	var pods core.PodList
	err = r.List(context.TODO(), &pods,
		client.InNamespace(mypod.Namespace),
		client.MatchingLabelsSelector{Selector: sel})
	if err != nil {
		return ctrl.Result{}, err
	}

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

	refs := sets.NewString()
	for _, pod := range pods.Items {
		for _, c := range pod.Status.ContainerStatuses {
			ref, err := fnRef(c)
			if err != nil {
				return ctrl.Result{}, err
			}
			refs.Insert(ref)
		}
		for _, c := range pod.Status.InitContainerStatuses {
			ref, err := fnRef(c)
			if err != nil {
				return ctrl.Result{}, err
			}
			refs.Insert(ref)
		}
		for _, c := range pod.Status.EphemeralContainerStatuses {
			ref, err := fnRef(c)
			if err != nil {
				return ctrl.Result{}, err
			}
			refs.Insert(ref)
		}
	}

	for _, ref := range refs.UnsortedList() {
		imageRef, err := name.ParseReference(ref)
		if err != nil {
			return ctrl.Result{}, err
		}

		if _, err := remote.Get(imageRef, remote.WithAuth(authn.Anonymous)); err == nil {
			backend.SubmitScanRequest(r.nc, "scanner.queue.scan", ref)
		}
	}

	return ctrl.Result{}, nil
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
			apps.SchemeGroupVersion.WithKind("Deployment"),
			apps.SchemeGroupVersion.WithKind("StatefulSet"),
			apps.SchemeGroupVersion.WithKind("DaemonSet"),
		).
		Complete(func() duck.Reconciler {
			wr := new(WorkloadReconciler)
			wr.nc = r.nc
			return wr
		})
}
