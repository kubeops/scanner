//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageReport) DeepCopyInto(out *ImageReport) {
	*out = *in
	if in.VulnerabilityInfos != nil {
		in, out := &in.VulnerabilityInfos, &out.VulnerabilityInfos
		*out = make([]VulnerabilityInfo, len(*in))
		copy(*out, *in)
	}
	if in.Pods != nil {
		in, out := &in.Pods, &out.Pods
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Containers != nil {
		in, out := &in.Containers, &out.Containers
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Lineage != nil {
		in, out := &in.Lineage, &out.Lineage
		*out = make([][]v1.OwnerReference, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = make([]v1.OwnerReference, len(*in))
				for i := range *in {
					(*in)[i].DeepCopyInto(&(*out)[i])
				}
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageReport.
func (in *ImageReport) DeepCopy() *ImageReport {
	if in == nil {
		return nil
	}
	out := new(ImageReport)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Report) DeepCopyInto(out *Report) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.Request != nil {
		in, out := &in.Request, &out.Request
		*out = new(ReportRequest)
		**out = **in
	}
	if in.Response != nil {
		in, out := &in.Response, &out.Response
		*out = new(ReportResponse)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Report.
func (in *Report) DeepCopy() *Report {
	if in == nil {
		return nil
	}
	out := new(Report)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Report) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReportRequest) DeepCopyInto(out *ReportRequest) {
	*out = *in
	out.ObjectInfo = in.ObjectInfo
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReportRequest.
func (in *ReportRequest) DeepCopy() *ReportRequest {
	if in == nil {
		return nil
	}
	out := new(ReportRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReportResponse) DeepCopyInto(out *ReportResponse) {
	*out = *in
	if in.Images != nil {
		in, out := &in.Images, &out.Images
		*out = make([]ImageReport, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Vulnerabilities != nil {
		in, out := &in.Vulnerabilities, &out.Vulnerabilities
		*out = make(map[string]int, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReportResponse.
func (in *ReportResponse) DeepCopy() *ReportResponse {
	if in == nil {
		return nil
	}
	out := new(ReportResponse)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VulnerabilityInfo) DeepCopyInto(out *VulnerabilityInfo) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VulnerabilityInfo.
func (in *VulnerabilityInfo) DeepCopy() *VulnerabilityInfo {
	if in == nil {
		return nil
	}
	out := new(VulnerabilityInfo)
	in.DeepCopyInto(out)
	return out
}
