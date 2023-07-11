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
	batch "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cu "kmodules.xyz/client-go/client"
	coreutil "kmodules.xyz/client-go/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *RequestReconciler) copyRequiredObjects() (string, []corev1.LocalObjectReference, error) {
	pullSecrets, err := r.copySecrets(r.req.Spec.PullSecrets)
	if err != nil {
		return "", nil, err
	}

	if r.req.Spec.ServiceAccountName == "" {
		return "", pullSecrets, nil
	}

	var sa corev1.ServiceAccount
	err = r.Client.Get(r.ctx, types.NamespacedName{
		Name:      r.req.Spec.ServiceAccountName,
		Namespace: r.req.Spec.Namespace,
	}, &sa)
	if err != nil {
		return "", nil, err
	}

	saPullSecrets, err := r.copySecrets(sa.ImagePullSecrets)
	if err != nil {
		return "", nil, err
	}

	newSA, err := r.copyServiceAccount(saPullSecrets, sa)
	if err != nil {
		return "", nil, err
	}

	return newSA, pullSecrets, nil
}

func (r *RequestReconciler) copySecrets(secrets []corev1.LocalObjectReference) ([]corev1.LocalObjectReference, error) {
	secList := make([]corev1.LocalObjectReference, 0)
	for _, secretName := range secrets {
		var sec corev1.Secret
		err := r.Client.Get(r.ctx, types.NamespacedName{
			Name:      secretName.Name,
			Namespace: r.req.Spec.Namespace,
		}, &sec)
		if err != nil {
			return nil, err
		}

		newSec, _, err := cu.CreateOrPatch(r.ctx, r.Client, &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: corev1.SchemeGroupVersion.String(),
				Kind:       "Secret",
			},
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "pull-secret-",
				Namespace:    r.workspace,
			},
		}, func(obj client.Object, createOp bool) client.Object {
			s := obj.(*corev1.Secret)
			if createOp {
				s.Immutable = sec.Immutable
				s.Type = sec.Type
			}
			s.Data = sec.Data
			s.StringData = sec.StringData
			return s
		})
		if err != nil {
			return nil, err
		}
		secList = append(secList, corev1.LocalObjectReference{Name: newSec.GetName()})
	}
	return secList, nil
}

func (r *RequestReconciler) copyServiceAccount(saPullSecrets []corev1.LocalObjectReference, sa corev1.ServiceAccount) (string, error) {
	newSA, _, err := cu.CreateOrPatch(r.ctx, r.Client, &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "sa-",
			Namespace:    r.workspace,
		},
	}, func(obj client.Object, createOp bool) client.Object {
		s := obj.(*corev1.ServiceAccount)
		if createOp {
			s.Secrets = sa.Secrets
			s.ImagePullSecrets = saPullSecrets
			s.AutomountServiceAccountToken = sa.AutomountServiceAccountToken
		}
		return s
	})
	if err != nil {
		return "", err
	}
	return newSA.GetName(), nil
}

func (r *RequestReconciler) setOwnerRefToCopiedObjects(job *batch.Job, sa string, pullSecrets []corev1.LocalObjectReference) error {
	for i := range pullSecrets {
		_, _, err := cu.CreateOrPatch(r.ctx, r.Client, &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: corev1.SchemeGroupVersion.String(),
				Kind:       "Secret",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      pullSecrets[i].Name,
				Namespace: r.workspace,
			},
		}, func(obj client.Object, createOp bool) client.Object {
			s := obj.(*corev1.Secret)
			coreutil.EnsureOwnerReference(&s.ObjectMeta, metav1.NewControllerRef(job, batch.SchemeGroupVersion.WithKind("Job")))
			return s
		})
		if err != nil {
			return err
		}
	}
	if sa == "" {
		return nil
	}
	_, _, err := cu.CreateOrPatch(r.ctx, r.Client, &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sa,
			Namespace: r.workspace,
		},
	}, func(obj client.Object, createOp bool) client.Object {
		s := obj.(*corev1.ServiceAccount)
		coreutil.EnsureOwnerReference(&s.ObjectMeta, metav1.NewControllerRef(job, batch.SchemeGroupVersion.WithKind("Job")))
		return s
	})
	return err
}
