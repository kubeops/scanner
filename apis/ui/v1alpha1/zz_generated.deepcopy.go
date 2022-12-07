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
func (in *CVSS) DeepCopyInto(out *CVSS) {
	*out = *in
	if in.Nvd != nil {
		in, out := &in.Nvd, &out.Nvd
		*out = new(CVSSNvd)
		**out = **in
	}
	if in.Redhat != nil {
		in, out := &in.Redhat, &out.Redhat
		*out = new(CVSSRedhat)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CVSS.
func (in *CVSS) DeepCopy() *CVSS {
	if in == nil {
		return nil
	}
	out := new(CVSS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CVSSNvd) DeepCopyInto(out *CVSSNvd) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CVSSNvd.
func (in *CVSSNvd) DeepCopy() *CVSSNvd {
	if in == nil {
		return nil
	}
	out := new(CVSSNvd)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CVSSRedhat) DeepCopyInto(out *CVSSRedhat) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CVSSRedhat.
func (in *CVSSRedhat) DeepCopy() *CVSSRedhat {
	if in == nil {
		return nil
	}
	out := new(CVSSRedhat)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageConfig) DeepCopyInto(out *ImageConfig) {
	*out = *in
	in.Created.DeepCopyInto(&out.Created)
	if in.History != nil {
		in, out := &in.History, &out.History
		*out = make([]ImageHistory, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	in.Rootfs.DeepCopyInto(&out.Rootfs)
	in.Config.DeepCopyInto(&out.Config)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageConfig.
func (in *ImageConfig) DeepCopy() *ImageConfig {
	if in == nil {
		return nil
	}
	out := new(ImageConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageHistory) DeepCopyInto(out *ImageHistory) {
	*out = *in
	in.Created.DeepCopyInto(&out.Created)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageHistory.
func (in *ImageHistory) DeepCopy() *ImageHistory {
	if in == nil {
		return nil
	}
	out := new(ImageHistory)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageMetadata) DeepCopyInto(out *ImageMetadata) {
	*out = *in
	out.Os = in.Os
	if in.DiffIDs != nil {
		in, out := &in.DiffIDs, &out.DiffIDs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.RepoTags != nil {
		in, out := &in.RepoTags, &out.RepoTags
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.RepoDigests != nil {
		in, out := &in.RepoDigests, &out.RepoDigests
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.ImageConfig.DeepCopyInto(&out.ImageConfig)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageMetadata.
func (in *ImageMetadata) DeepCopy() *ImageMetadata {
	if in == nil {
		return nil
	}
	out := new(ImageMetadata)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageOS) DeepCopyInto(out *ImageOS) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageOS.
func (in *ImageOS) DeepCopy() *ImageOS {
	if in == nil {
		return nil
	}
	out := new(ImageOS)
	in.DeepCopyInto(out)
	return out
}

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
func (in *ImageRootfs) DeepCopyInto(out *ImageRootfs) {
	*out = *in
	if in.DiffIds != nil {
		in, out := &in.DiffIds, &out.DiffIds
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageRootfs.
func (in *ImageRootfs) DeepCopy() *ImageRootfs {
	if in == nil {
		return nil
	}
	out := new(ImageRootfs)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageRuntimeConfig) DeepCopyInto(out *ImageRuntimeConfig) {
	*out = *in
	if in.Cmd != nil {
		in, out := &in.Cmd, &out.Cmd
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Env != nil {
		in, out := &in.Env, &out.Env
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Entrypoint != nil {
		in, out := &in.Entrypoint, &out.Entrypoint
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageRuntimeConfig.
func (in *ImageRuntimeConfig) DeepCopy() *ImageRuntimeConfig {
	if in == nil {
		return nil
	}
	out := new(ImageRuntimeConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageScanReport) DeepCopyInto(out *ImageScanReport) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageScanReport.
func (in *ImageScanReport) DeepCopy() *ImageScanReport {
	if in == nil {
		return nil
	}
	out := new(ImageScanReport)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ImageScanReport) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageScanReportSpec) DeepCopyInto(out *ImageScanReportSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageScanReportSpec.
func (in *ImageScanReportSpec) DeepCopy() *ImageScanReportSpec {
	if in == nil {
		return nil
	}
	out := new(ImageScanReportSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageScanReportStatus) DeepCopyInto(out *ImageScanReportStatus) {
	*out = *in
	in.LastChecked.DeepCopyInto(&out.LastChecked)
	in.Report.DeepCopyInto(&out.Report)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageScanReportStatus.
func (in *ImageScanReportStatus) DeepCopy() *ImageScanReportStatus {
	if in == nil {
		return nil
	}
	out := new(ImageScanReportStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageScanRequest) DeepCopyInto(out *ImageScanRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.Request != nil {
		in, out := &in.Request, &out.Request
		*out = new(ImageScanRequestSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageScanRequest.
func (in *ImageScanRequest) DeepCopy() *ImageScanRequest {
	if in == nil {
		return nil
	}
	out := new(ImageScanRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ImageScanRequest) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageScanRequestSpec) DeepCopyInto(out *ImageScanRequestSpec) {
	*out = *in
	if in.PullSecrets != nil {
		in, out := &in.PullSecrets, &out.PullSecrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageScanRequestSpec.
func (in *ImageScanRequestSpec) DeepCopy() *ImageScanRequestSpec {
	if in == nil {
		return nil
	}
	out := new(ImageScanRequestSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MyTime.
func (in *MyTime) DeepCopy() *MyTime {
	if in == nil {
		return nil
	}
	out := new(MyTime)
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
func (in *Result) DeepCopyInto(out *Result) {
	*out = *in
	if in.Vulnerabilities != nil {
		in, out := &in.Vulnerabilities, &out.Vulnerabilities
		*out = make([]Vulnerability, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Result.
func (in *Result) DeepCopy() *Result {
	if in == nil {
		return nil
	}
	out := new(Result)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanSummary) DeepCopyInto(out *ScanSummary) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.Request != nil {
		in, out := &in.Request, &out.Request
		*out = new(ScanSummaryRequest)
		**out = **in
	}
	if in.Response != nil {
		in, out := &in.Response, &out.Response
		*out = new(ScanSummaryResponse)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanSummary.
func (in *ScanSummary) DeepCopy() *ScanSummary {
	if in == nil {
		return nil
	}
	out := new(ScanSummary)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ScanSummary) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanSummaryRequest) DeepCopyInto(out *ScanSummaryRequest) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanSummaryRequest.
func (in *ScanSummaryRequest) DeepCopy() *ScanSummaryRequest {
	if in == nil {
		return nil
	}
	out := new(ScanSummaryRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanSummaryResponse) DeepCopyInto(out *ScanSummaryResponse) {
	*out = *in
	in.Result.DeepCopyInto(&out.Result)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanSummaryResponse.
func (in *ScanSummaryResponse) DeepCopy() *ScanSummaryResponse {
	if in == nil {
		return nil
	}
	out := new(ScanSummaryResponse)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SingleReport) DeepCopyInto(out *SingleReport) {
	*out = *in
	in.Metadata.DeepCopyInto(&out.Metadata)
	if in.Results != nil {
		in, out := &in.Results, &out.Results
		*out = make([]Result, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SingleReport.
func (in *SingleReport) DeepCopy() *SingleReport {
	if in == nil {
		return nil
	}
	out := new(SingleReport)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Summary) DeepCopyInto(out *Summary) {
	*out = *in
	in.Metadata.DeepCopyInto(&out.Metadata)
	if in.Results != nil {
		in, out := &in.Results, &out.Results
		*out = make([]SummaryResult, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Summary.
func (in *Summary) DeepCopy() *Summary {
	if in == nil {
		return nil
	}
	out := new(Summary)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SummaryResult) DeepCopyInto(out *SummaryResult) {
	*out = *in
	if in.Vulnerabilities != nil {
		in, out := &in.Vulnerabilities, &out.Vulnerabilities
		*out = make(map[string]int, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SummaryResult.
func (in *SummaryResult) DeepCopy() *SummaryResult {
	if in == nil {
		return nil
	}
	out := new(SummaryResult)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Vulnerability) DeepCopyInto(out *Vulnerability) {
	*out = *in
	out.Layer = in.Layer
	out.DataSource = in.DataSource
	if in.CweIDs != nil {
		in, out := &in.CweIDs, &out.CweIDs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.Cvss.DeepCopyInto(&out.Cvss)
	if in.References != nil {
		in, out := &in.References, &out.References
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.PublishedDate != nil {
		in, out := &in.PublishedDate, &out.PublishedDate
		*out = (*in).DeepCopy()
	}
	if in.LastModifiedDate != nil {
		in, out := &in.LastModifiedDate, &out.LastModifiedDate
		*out = (*in).DeepCopy()
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Vulnerability.
func (in *Vulnerability) DeepCopy() *Vulnerability {
	if in == nil {
		return nil
	}
	out := new(Vulnerability)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VulnerabilityDataSource) DeepCopyInto(out *VulnerabilityDataSource) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VulnerabilityDataSource.
func (in *VulnerabilityDataSource) DeepCopy() *VulnerabilityDataSource {
	if in == nil {
		return nil
	}
	out := new(VulnerabilityDataSource)
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

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VulnerabilityLayer) DeepCopyInto(out *VulnerabilityLayer) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VulnerabilityLayer.
func (in *VulnerabilityLayer) DeepCopy() *VulnerabilityLayer {
	if in == nil {
		return nil
	}
	out := new(VulnerabilityLayer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Workload) DeepCopyInto(out *Workload) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Workload.
func (in *Workload) DeepCopy() *Workload {
	if in == nil {
		return nil
	}
	out := new(Workload)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Workload) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadList) DeepCopyInto(out *WorkloadList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Workload, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadList.
func (in *WorkloadList) DeepCopy() *WorkloadList {
	if in == nil {
		return nil
	}
	out := new(WorkloadList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WorkloadList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadSpec) DeepCopyInto(out *WorkloadSpec) {
	*out = *in
	if in.Selector != nil {
		in, out := &in.Selector, &out.Selector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	in.Template.DeepCopyInto(&out.Template)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadSpec.
func (in *WorkloadSpec) DeepCopy() *WorkloadSpec {
	if in == nil {
		return nil
	}
	out := new(WorkloadSpec)
	in.DeepCopyInto(out)
	return out
}