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
	"fmt"
	"strings"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"

	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	cu "kmodules.xyz/client-go/client"
	"kmodules.xyz/client-go/client/apiutil"
	core_util "kmodules.xyz/client-go/core/v1"
	coreapi "kmodules.xyz/client-go/core/v1"
	"kmodules.xyz/go-containerregistry/name"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ScannerJobName   = "scan-image"
	SharedVolumeName = "shared-disk"
	WorkDir          = "/root/.cache"

	containerTrivyCLI = "trivy"
	containerTrivyDB  = "trivydb"
	containerScanner  = "scanner"
	containerUploader = "uploader"
)

func (r *RequestReconciler) ensureJob(sa string, pullSecrets []corev1.LocalObjectReference) (*batch.Job, error) {
	if r.req.Status.JobName != "" {
		var job batch.Job
		err := r.Client.Get(r.ctx, types.NamespacedName{
			Name:      r.req.Status.JobName,
			Namespace: r.workspace,
		}, &job)
		if err != nil {
			return nil, err
		}
		return &job, nil
	}

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

	obj := &batch.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: batch.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: ScannerJobName,
			Namespace:    r.workspace,
		},
	}
	_, err := cu.CreateOrPatch(r.ctx, r.Client, obj, func(obj client.Object, createOp bool) client.Object {
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
					Name:       containerTrivyCLI,
					Image:      r.trivyImage,
					WorkingDir: WorkDir,
					Command: []string{
						"cp",
						"/usr/local/bin/trivy",
						"tv",
					},
				},
				{
					Name:       containerTrivyDB,
					Image:      r.trivyDBCacherImage,
					WorkingDir: WorkDir,
					Command: []string{
						"/scripts/extract.sh",
					},
					ImagePullPolicy: core.PullIfNotPresent,
					Env: []core.EnvVar{
						{
							Name:  "FILESERVER_ADDR",
							Value: r.fileServerAddr,
						},
					},
				},
				{
					Name:       containerScanner,
					Image:      r.req.Spec.Image,
					WorkingDir: WorkDir,
					Command: []string{
						"sh",
						"-c",
						"./tv rootfs --skip-db-update --skip-java-db-update --offline-scan --security-checks vuln --format json / > report.json && ./tv version --format json > trivy.json",
					},
					SecurityContext: &core.SecurityContext{
						RunAsUser:    ptr.To(int64(0)),
						RunAsGroup:   ptr.To(int64(0)),
						RunAsNonRoot: nil,
						SeccompProfile: &core.SeccompProfile{
							Type: core.SeccompProfileTypeRuntimeDefault,
						},
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
			})
			job.Spec.Template.Spec.Containers = core_util.UpsertContainers(job.Spec.Template.Spec.Containers, []core.Container{
				{
					Name:       containerUploader,
					Image:      r.scannerImage,
					WorkingDir: WorkDir,
					Command: []string{
						"sh",
						"-c",
						fmt.Sprintf("/scanner upload-report --report-file report.json --trivy-file trivy.json --image %s > output.txt && cat output.txt", r.req.Spec.Image),
					},
					ImagePullPolicy: core.PullIfNotPresent,
				},
			})
			ensureVolumeMounts(&job.Spec.Template)
		}
		job.Spec.Template.Spec.AutomountServiceAccountToken = ptr.To(true)
		job.Spec.Template.Spec.RestartPolicy = core.RestartPolicyNever
		job.Spec.Template.Spec.ImagePullSecrets = pullSecrets
		job.Spec.Template.Spec.ServiceAccountName = sa
		job.Spec.TTLSecondsAfterFinished = ptr.To(int32(600))
		return job
	})
	if err != nil {
		return nil, err
	}

	klog.Infof("Scanner job %v/%v created", obj.GetNamespace(), obj.GetName())
	return obj, r.updateStatusWithJobName(obj.GetName())
}

func (r *RequestReconciler) ScanForPrivateImage() error {
	sa, pullSecrets, err := r.copyRequiredObjects()
	if err != nil {
		return err
	}

	job, err := r.ensureJob(sa, pullSecrets)
	if err != nil {
		return err
	}

	return r.setOwnerRefToCopiedObjects(job, sa, pullSecrets)
}

func (r *RequestReconciler) getPrivateImageScannerJob() (*batch.Job, error) {
	var job batch.Job
	err := r.Get(r.ctx, types.NamespacedName{
		Name:      r.req.Status.JobName,
		Namespace: r.workspace,
	}, &job)
	return &job, err
}

func (r *RequestReconciler) getPrivateImageScannerPod(job *batch.Job) (*corev1.Pod, error) {
	var podList corev1.PodList
	podSelectors := job.Spec.Template.Labels
	err := r.List(r.ctx, &podList, &client.ListOptions{
		LabelSelector: labels.Set(podSelectors).AsSelector(),
		Namespace:     job.Namespace,
	})
	if err != nil {
		return nil, err
	}
	for _, pod := range podList.Items {
		owned, _ := coreapi.IsOwnedBy(&pod, job)
		if owned {
			return &pod, nil
		}
	}
	return nil, nil
}

func (r *RequestReconciler) getPrivateImageScannerInitContainer(pod *corev1.Pod) (corev1.Container, corev1.ContainerStatus, bool) {
	var (
		container       corev1.Container
		containerStatus corev1.ContainerStatus
		found           bool
	)
	if pod == nil {
		return container, containerStatus, found
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == containerScanner {
			container = c
		}
	}
	for _, c := range pod.Status.InitContainerStatuses {
		if c.Name == containerScanner {
			containerStatus = c
			found = true
		}
	}
	return container, containerStatus, found
}

func (r *RequestReconciler) getDigestForPrivateImage(pod *core.Pod) (string, error) {
	c, cs, found := r.getPrivateImageScannerInitContainer(pod)
	if !found { // pod has just been created, so we need to wait
		return "", nil
	}
	ref, err := apiutil.GetImageRef(c.Image, cs.Image, cs.ImageID)
	if err != nil {
		return "", err
	}

	splits := strings.Split(ref, "@")
	if len(splits) == 2 { // this will be true for all the images except for the kind-loaded ones
		return splits[1], nil
	}
	// TODO: What if it is a kind-loaded image ? For now, returning empty string
	return "", nil
}

func (r *RequestReconciler) ensureDigestInRequestAndReport(digest string) error {
	if digest == "" {
		return nil
	}
	img, err := name.ParseReference(r.req.Spec.Image)
	if err != nil {
		return err
	}

	r.req = &api.ImageScanRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.req.Name,
		},
	}
	_, err = cu.PatchStatus(r.ctx, r.Client, r.req, func(obj client.Object) client.Object {
		req := obj.(*api.ImageScanRequest)
		if req.Status.Image == nil {
			req.Status.Image = &trivy.ImageDetails{
				Name:       img.Name,
				Tag:        img.Tag,
				Digest:     img.Digest,
				Visibility: trivy.ImageVisibilityPrivate,
			}
		}
		req.Status.Image.Digest = digest
		return req
	})
	if err != nil {
		return err
	}

	_, err = cu.CreateOrPatch(r.ctx, r.Client, &api.ImageScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: api.GetReportName(img.Name),
		},
	}, func(obj client.Object, createOp bool) client.Object {
		rep := obj.(*api.ImageScanReport)
		rep.Spec.Image.Digest = digest
		return rep
	})
	return err
}
