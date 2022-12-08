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
	"fmt"

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

type ImageInfo struct {
	Image string `json:"image"`
	ImageMeta
}

type ImageMeta struct {
	Namespace        string                      `json:"namespace"`
	ImagePullSecrets []core.LocalObjectReference `json:"imagePullSecrets"`
}

func NewImageInfo(img string, meta ImageMeta) ImageInfo {
	return ImageInfo{
		Image:     img,
		ImageMeta: meta,
	}
}

const (
	ScannerJobName   = "scan-image"
	SharedVolumeName = "shared-disk"
	TrivyImageName   = "trivy"
	TrivyImage       = "aquasec/trivy"
	WorkDir          = "/root/.cache"

	NatsCLIImageName  = "trivydb"
	NatsCLIImage      = "arnobkumarsaha/natscli"
	UserImageName     = "scanner"
	UploaderImageName = "uploader"
)

func (r *WorkloadReconciler) ScanForPrivateImage(info ImageInfo) error {
	ensureVolumeMounts := func(pt *core.PodTemplateSpec) {
		mount := core.VolumeMount{
			MountPath: WorkDir,
			Name:      SharedVolumeName,
		}
		for i := range pt.Spec.InitContainers {
			pt.Spec.InitContainers[i].VolumeMounts = core_util.UpsertVolumeMount(pt.Spec.InitContainers[i].VolumeMounts, mount)
		}
		for i := range pt.Spec.Containers {
			pt.Spec.Containers[i].VolumeMounts = core_util.UpsertVolumeMount(pt.Spec.Containers[i].VolumeMounts, mount)
		}
	}

	obj, vt, err := cu.CreateOrPatch(context.TODO(), r.Client, &batch.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ScannerJobName,
			Namespace: info.Namespace,
		},
	}, func(obj client.Object, createOp bool) client.Object {
		job := obj.(*batch.Job)
		if createOp {
			job.Spec.Template.Spec.Volumes = core_util.UpsertVolume(job.Spec.Template.Spec.Volumes, core.Volume{
				Name: SharedVolumeName,
				VolumeSource: core.VolumeSource{
					EmptyDir: &core.EmptyDirVolumeSource{},
				},
			})
			job.Spec.Template.Spec.InitContainers = core_util.UpsertContainers(job.Spec.Template.Spec.InitContainers, []core.Container{
				{
					Name:       TrivyImageName,
					Image:      TrivyImage,
					WorkingDir: WorkDir,
					Command: []string{
						"cp",
						"/usr/local/bin/trivy",
						"tv",
					},
				},
				{
					Name:       NatsCLIImageName,
					Image:      NatsCLIImage,
					WorkingDir: WorkDir,
					Command: []string{
						"/scripts/extract.sh",
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
				{
					Name:       UserImageName,
					Image:      info.Image,
					WorkingDir: WorkDir,
					Command: []string{
						"sh",
						"-c",
						"./tv rootfs --skip-update --security-checks vuln --format json / > report.json && ./tv version -f json > trivy.json",
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
			})
			job.Spec.Template.Spec.Containers = core_util.UpsertContainers(job.Spec.Template.Spec.Containers, []core.Container{
				{
					Name:       UploaderImageName,
					Image:      r.scannerImage,
					WorkingDir: WorkDir,
					Command: []string{
						fmt.Sprintf("scanner upload-report --report-file report.json --trivy-file trivy.json --image  %s", info.Image),
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
			})
			ensureVolumeMounts(&job.Spec.Template)
		}
		job.Spec.Template.Spec.RestartPolicy = core.RestartPolicyNever
		job.Spec.Template.Spec.ImagePullSecrets = info.ImagePullSecrets
		job.Spec.TTLSecondsAfterFinished = pointer.Int32(100)
		return job
	})
	if err != nil {
		return err
	}
	if vt == kutil.VerbCreated {
		klog.Infof("Scanner job %v/%v created", obj.GetNamespace(), obj.GetName())
	}
	return nil
}
