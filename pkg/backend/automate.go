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

package backend

import (
	"context"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
	kutil "kmodules.xyz/client-go"
	cu "kmodules.xyz/client-go/client"
	core_util "kmodules.xyz/client-go/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NATSObjectStoreName = "trivy"
)

func CheckPrivateImage(imageRef name.Reference) (bool, error) {
	_, err := remote.Get(imageRef, remote.WithAuth(authn.Anonymous))
	if err == nil {
		return false, nil
	}
	if strings.Contains(err.Error(), "UNAUTHORIZED") {
		return true, nil
	}
	return true, err
}

const (
	CronJobName    = "refersh-trivydb"
	ContainerName  = "trivydb"
	ContainerImage = "arnobkumarsaha/natscli:latest"
)

func EnsureCronJobToRefreshTrivyDB(c client.Client) error {
	obj, vt, err := cu.CreateOrPatch(context.TODO(), c, &batch.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CronJobName,
			Namespace: "default",
		},
	}, func(obj client.Object, createOp bool) client.Object {
		cj := obj.(*batch.CronJob)

		cj.Spec.Schedule = "0 */6 * * *" // every 6 hours
		cj.Spec.JobTemplate.Spec.BackoffLimit = pointer.Int32(2)
		cj.Spec.JobTemplate.Spec.Selector = nil
		cj.Spec.JobTemplate.Spec.Template.Spec.Containers = core_util.UpsertContainers(cj.Spec.JobTemplate.Spec.Template.Spec.Containers, []core.Container{
			{
				Name:            ContainerName,
				Image:           ContainerImage,
				ImagePullPolicy: core.PullIfNotPresent,
				Command: []string{
					"/scripts/update-trivydb.sh",
				},
			},
		})
		cj.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy = core.RestartPolicyNever
		return cj
	})
	if err != nil {
		return err
	}
	if vt == kutil.VerbCreated {
		klog.Infof("Cronjob %v created", obj.GetName())
	}
	return nil
}
