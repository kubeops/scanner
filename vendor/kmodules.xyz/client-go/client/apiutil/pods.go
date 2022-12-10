/*
Copyright AppsCode Inc. and Contributors

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

package apiutil

import (
	"context"
	"fmt"
	"strings"

	kmapi "kmodules.xyz/client-go/api/v1"

	"github.com/google/go-containerregistry/pkg/name"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Container struct {
	Name  string
	Image string
}

func CollectImageInfo(kc client.Client, pod *core.Pod, images map[string]kmapi.ImageInfo) error {
	objKey := client.ObjectKeyFromObject(pod).String()

	lineage, err := DetectLineage(context.TODO(), kc, pod)
	if err != nil {
		return err
	}

	refs := map[string][]string{}
	for _, c := range pod.Spec.Containers {
		ref, err := GetImageRef(objKey, Container{Name: c.Name, Image: c.Image}, FindContainerStatus(c.Name, pod.Status.ContainerStatuses))
		if err != nil {
			return err
		}
		refs[ref] = append(refs[ref], c.Name)
	}
	for _, c := range pod.Spec.InitContainers {
		ref, err := GetImageRef(objKey, Container{Name: c.Name, Image: c.Image}, FindContainerStatus(c.Name, pod.Status.InitContainerStatuses))
		if err != nil {
			return err
		}
		refs[ref] = append(refs[ref], c.Name)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		ref, err := GetImageRef(objKey, Container{Name: c.Name, Image: c.Image}, nil)
		if err != nil {
			return err
		}
		refs[ref] = append(refs[ref], c.Name)
	}

	for ref, containers := range refs {
		iu, ok := images[ref]
		if !ok {
			iu = kmapi.ImageInfo{
				Image:    ref,
				Lineages: nil,
				PullSecrets: &kmapi.PullSecrets{
					Namespace: pod.Namespace,
					Refs:      pod.Spec.ImagePullSecrets,
				},
			}
			images[ref] = iu
		}
		iu.Lineages = append(iu.Lineages, kmapi.Lineage{
			Chain:      lineage,
			Containers: containers,
		})
	}

	return nil
}

func CollectPullSecrets(pod *core.Pod, refs map[string]kmapi.PullSecrets) error {
	objKey := client.ObjectKeyFromObject(pod).String()
	for _, c := range pod.Status.ContainerStatuses {
		ref, err := GetImageRef(objKey, Container{Name: c.Name, Image: c.ImageID}, FindContainerStatus(c.Name, pod.Status.ContainerStatuses))
		if err != nil {
			return err
		}
		refs[ref] = kmapi.PullSecrets{
			Namespace: pod.Namespace,
			Refs:      pod.Spec.ImagePullSecrets,
		}
	}
	for _, c := range pod.Status.InitContainerStatuses {
		ref, err := GetImageRef(objKey, Container{Name: c.Name, Image: c.ImageID}, FindContainerStatus(c.Name, pod.Status.InitContainerStatuses))
		if err != nil {
			return err
		}
		refs[ref] = kmapi.PullSecrets{
			Namespace: pod.Namespace,
			Refs:      pod.Spec.ImagePullSecrets,
		}
	}
	for _, c := range pod.Status.EphemeralContainerStatuses {
		ref, err := GetImageRef(objKey, Container{Name: c.Name, Image: c.ImageID}, nil)
		if err != nil {
			return err
		}
		refs[ref] = kmapi.PullSecrets{
			Namespace: pod.Namespace,
			Refs:      pod.Spec.ImagePullSecrets,
		}
	}

	return nil
}

func GetImageRef(pod string, c Container, status *core.ContainerStatus) (string, error) {
	var img string

	if strings.ContainsRune(c.Image, '@') || strings.HasPrefix(status.ImageID, "sha256:") {
		img = c.Image
	} else if strings.ContainsRune(status.Image, '@') {
		img = status.Image
	} else if strings.Contains(status.ImageID, "://") {
		img = status.ImageID[strings.Index(status.ImageID, "://")+3:] // docker-pullable://, Linode
	} else {
		_, digest, ok := strings.Cut(status.ImageID, "@")
		if !ok {
			return "", fmt.Errorf("missing digest in pod %s container %s imageID %s", pod, status.Name, status.ImageID)
		}
		img = c.Image + "@" + digest
	}
	ref, err := name.ParseReference(img)
	if err != nil {
		return "", err
	}
	return ref.Context().String() + "@" + ref.Identifier(), nil
}

func FindContainerStatus(name string, statuses []core.ContainerStatus) *core.ContainerStatus {
	for i := range statuses {
		if statuses[i].Name == name {
			return &statuses[i]
		}
	}
	return nil
}

func DetectLineage(ctx context.Context, kc client.Client, obj client.Object) ([]kmapi.ObjectInfo, error) {
	var result []kmapi.ObjectInfo
	if err := findLineage(ctx, kc, obj, result); err != nil {
		return nil, err
	}
	return result, nil
}

func findLineage(ctx context.Context, kc client.Client, obj client.Object, result []kmapi.ObjectInfo) error {
	ref := metav1.GetControllerOfNoCopy(obj)
	if ref != nil {
		var owner unstructured.Unstructured
		owner.SetAPIVersion(ref.APIVersion)
		owner.SetKind(ref.Kind)
		if err := kc.Get(ctx, client.ObjectKey{Namespace: obj.GetNamespace(), Name: ref.Name}, &owner); err != nil {
			return err
		}
		if err := findLineage(ctx, kc, &owner, result); err != nil {
			return err
		}
	}

	gvk := obj.GetObjectKind().GroupVersionKind()
	result = append(result, kmapi.ObjectInfo{
		Resource: kmapi.ResourceID{
			Group:   gvk.Group,
			Version: gvk.Version,
			Name:    "",
			Kind:    gvk.Kind,
			Scope:   "",
		},
		Ref: kmapi.ObjectReference{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		},
	})
	return nil
}
