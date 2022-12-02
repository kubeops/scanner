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

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
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
	ScannerPodName   = "scan-image"
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
	ensureVolumeMounts := func(pod *core.Pod) {
		mount := core.VolumeMount{
			MountPath: WorkDir,
			Name:      SharedVolumeName,
		}
		for i := range pod.Spec.InitContainers {
			pod.Spec.InitContainers[i].VolumeMounts = core_util.UpsertVolumeMount(pod.Spec.InitContainers[i].VolumeMounts, mount)
		}
		for i := range pod.Spec.Containers {
			pod.Spec.Containers[i].VolumeMounts = core_util.UpsertVolumeMount(pod.Spec.Containers[i].VolumeMounts, mount)
		}
	}

	obj, vt, err := cu.CreateOrPatch(context.TODO(), r.Client, &core.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ScannerPodName,
			Namespace: info.Namespace,
		},
	}, func(obj client.Object, createOp bool) client.Object {
		pod := obj.(*core.Pod)
		if createOp {
			pod.Spec.Volumes = core_util.UpsertVolume(pod.Spec.Volumes, core.Volume{
				Name: SharedVolumeName,
				VolumeSource: core.VolumeSource{
					EmptyDir: &core.EmptyDirVolumeSource{},
				},
			})
			pod.Spec.InitContainers = core_util.UpsertContainers(pod.Spec.InitContainers, []core.Container{
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
						"./tv rootfs --skip-update --security-checks vuln --format json / > report.json",
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
			})
			pod.Spec.Containers = core_util.UpsertContainers(pod.Spec.Containers, []core.Container{
				{
					Name:       UploaderImageName,
					Image:      NatsCLIImage,
					WorkingDir: WorkDir,
					Command: []string{
						"/scripts/upload-report.sh",
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
			})
			ensureVolumeMounts(pod)
		}
		pod.Spec.RestartPolicy = core.RestartPolicyNever
		pod.Spec.ImagePullSecrets = info.ImagePullSecrets
		return pod
	})
	if err != nil {
		return err
	}
	if vt == kutil.VerbCreated {
		klog.Infof("Scanner pod %v/%v created", obj.GetNamespace(), obj.GetName())
	}
	return nil
}
