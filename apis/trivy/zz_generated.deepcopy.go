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

package trivy

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BackendResponse) DeepCopyInto(out *BackendResponse) {
	*out = *in
	in.Report.DeepCopyInto(&out.Report)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BackendResponse.
func (in *BackendResponse) DeepCopy() *BackendResponse {
	if in == nil {
		return nil
	}
	out := new(BackendResponse)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CVSSScore) DeepCopyInto(out *CVSSScore) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CVSSScore.
func (in *CVSSScore) DeepCopy() *CVSSScore {
	if in == nil {
		return nil
	}
	out := new(CVSSScore)
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
func (in *ImageResult) DeepCopyInto(out *ImageResult) {
	*out = *in
	if in.Targets != nil {
		in, out := &in.Targets, &out.Targets
		*out = make([]Target, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageResult.
func (in *ImageResult) DeepCopy() *ImageResult {
	if in == nil {
		return nil
	}
	out := new(ImageResult)
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
	in.LastModificationTime.DeepCopyInto(&out.LastModificationTime)
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
func (in *Target) DeepCopyInto(out *Target) {
	*out = *in
	if in.Layer != nil {
		in, out := &in.Layer, &out.Layer
		*out = new(VulnerabilityLayer)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Target.
func (in *Target) DeepCopy() *Target {
	if in == nil {
		return nil
	}
	out := new(Target)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Version) DeepCopyInto(out *Version) {
	*out = *in
	in.VulnerabilityDB.DeepCopyInto(&out.VulnerabilityDB)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Version.
func (in *Version) DeepCopy() *Version {
	if in == nil {
		return nil
	}
	out := new(Version)
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
	if in.Cvss != nil {
		in, out := &in.Cvss, &out.Cvss
		*out = make(map[string]CVSSScore, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
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
func (in *VulnerabilityDBStruct) DeepCopyInto(out *VulnerabilityDBStruct) {
	*out = *in
	in.UpdatedAt.DeepCopyInto(&out.UpdatedAt)
	in.DownloadedAt.DeepCopyInto(&out.DownloadedAt)
	in.NextUpdate.DeepCopyInto(&out.NextUpdate)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VulnerabilityDBStruct.
func (in *VulnerabilityDBStruct) DeepCopy() *VulnerabilityDBStruct {
	if in == nil {
		return nil
	}
	out := new(VulnerabilityDBStruct)
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
	if in.Results != nil {
		in, out := &in.Results, &out.Results
		*out = make([]ImageResult, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.R != nil {
		in, out := &in.R, &out.R
		*out = make(map[string]ImageResult, len(*in))
		for key, val := range *in {
			(*out)[key] = *val.DeepCopy()
		}
	}
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
