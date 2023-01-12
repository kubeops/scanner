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
	"encoding/json"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"kubeops.dev/scanner/apis/trivy"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	_ "gocloud.dev/blob/s3blob"
	"gomodules.xyz/blobfs"
	shell "gomodules.xyz/go-sh"
	"k8s.io/klog/v2"
)

func NewBlobFS() blobfs.Interface {
	// https://www.linode.com/docs/products/storage/object-storage/guides/s3cmd/
	// "s3://my-bucket?region=us-west-1&awssdk=2"
	// s3://scanner-reports?endpoint=https://us-east-1.linodeobjects.com&region=US
	/*
		bucket, err := blob.OpenBucket("s3://mybucket?" +
		    "endpoint=my.minio.local:8080&" +
		    "disableSSL=true&" +
		    "s3ForcePathStyle=true")
	*/
	if _, ok := os.LookupEnv("AWS_ACCESS_KEY_ID"); !ok {
		_ = os.Setenv("AWS_ACCESS_KEY_ID", os.Getenv("LINODE_CLI_OBJ_ACCESS_KEY"))
	}
	if _, ok := os.LookupEnv("AWS_SECRET_ACCESS_KEY"); !ok {
		_ = os.Setenv("AWS_SECRET_ACCESS_KEY", os.Getenv("LINODE_CLI_OBJ_SECRET_KEY"))
	}

	storeURL := "s3://scanner-reports?endpoint=https://us-east-1.linodeobjects.com&region=US"
	return blobfs.New(storeURL)
}

func (mgr *Manager) getBucketResponse(img string) (*trivy.BackendResponse, error) {
	data, err := mgr.read(img)
	if err != nil {
		return nil, err
	}
	var resp trivy.BackendResponse
	err = trivy.JSON.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (mgr *Manager) read(img string) ([]byte, error) {
	klog.InfoS("working on", "image", img)
	data, err := ReadFromBucket(mgr.fs, img)
	if err != nil {
		s := ErrorToAPIStatus(err)
		data, _ = json.Marshal(s)
		if s.Code == http.StatusNotFound {
			err = mgr.submitScanRequest(img)
			if err != nil {
				klog.ErrorS(err, "failed to parse or get", "image", img)
				return nil, err
			}
		} else if s.Code == http.StatusTooManyRequests {
			go func() {
				time.Sleep(dockerHubRateLimitDelay)
				err = mgr.submitScanRequest(img)
				if err != nil {
					klog.ErrorS(err, "failed to parse or get", "image", img)
					return
				}
			}()
		}
	}
	return data, err
}

const ReportFileName = "report.json"

func ReadFromBucket(fs blobfs.Interface, img string) ([]byte, error) {
	repo, digest, err := ParseReference(img)
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(context.TODO(), path.Join(repo, digest, ReportFileName))
}

func ExistsReport(fs blobfs.Interface, img string) (bool, error) {
	repo, digest, err := ParseReference(img)
	if err != nil {
		return false, err
	}
	exists, err := fs.Exists(context.TODO(), path.Join(repo, digest, ReportFileName))
	if err != nil || !exists {
		return false, err
	}

	//// If file exists, & it is more than 6 hours old, We consider it as if it doesn't exist.
	read, err := fs.ReadFile(context.TODO(), path.Join(repo, digest, ReportFileName))
	if err != nil {
		return false, err
	}
	var res trivy.BackendResponse
	err = trivy.JSON.Unmarshal(read, &res)
	if err != nil {
		return false, err
	}
	if time.Since(res.Report.LastModificationTime.Time) > time.Hour*6 {
		return false, nil
	}
	return true, nil
}

func UploadReport(fs blobfs.Interface, img string) error {
	rep, _, err := scan(img)
	if err != nil {
		return err
	}

	repo, digest, err := ParseReference(img)
	if err != nil {
		return err
	}

	ver, err := getVersionInfo()
	if err != nil {
		return err
	}

	resp := trivy.BackendResponse{
		Report:       *rep,
		TrivyVersion: *ver,
		Visibility:   trivy.BackendVisibilityPublic,
	}
	marshaledResp, err := trivy.JSON.Marshal(&resp)
	if err != nil {
		return err
	}

	return fs.WriteFile(context.TODO(), path.Join(repo, digest, ReportFileName), marshaledResp)
}

// trivy image ubuntu --security-checks vuln --format json --quiet
func scan(img string) (*trivy.SingleReport, []byte, error) {
	sh := shell.NewSession()
	// sh.SetEnv("BUILD_ID", "123")
	sh.SetDir("/tmp")

	sh.ShowCMD = true
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr

	args := []any{
		"image",
		img,
		"--security-checks", "vuln",
		"--format", "json",
		// "--quiet",
	}
	out, err := sh.Command("trivy", args...).Output()
	if err != nil {
		return nil, nil, err
	}

	var r trivy.SingleReport
	err = trivy.JSON.Unmarshal(out, &r)
	if err != nil {
		return nil, nil, err
	}
	r.LastModificationTime = trivy.Time{Time: time.Now()}
	out, err = trivy.JSON.Marshal(r)
	if err != nil {
		return nil, nil, err
	}

	return &r, out, nil
}

func getVersionInfo() (*trivy.Version, error) {
	sh := shell.NewSession()
	sh.SetDir("/tmp")

	sh.ShowCMD = true
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr

	args := []any{
		"version",
		"--format", "json",
	}
	out, err := sh.Command("trivy", args...).Output()
	if err != nil {
		return nil, err
	}

	var ver trivy.Version
	err = trivy.JSON.Unmarshal(out, &ver)
	if err != nil {
		return nil, err
	}

	return &ver, nil
}

func ParseReference(img string) (repo string, digest string, err error) {
	ref, err := name.ParseReference(img)
	if err != nil {
		return
	}
	repo = ref.Context().String()
	if strings.HasPrefix(ref.Identifier(), "sha256:") {
		digest = ref.Identifier()
		return
	}
	digest, err = crane.Digest(img)
	return
}
