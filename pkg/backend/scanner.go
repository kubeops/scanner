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
	"time"

	"kubeops.dev/scanner/apis/trivy"

	_ "gocloud.dev/blob/s3blob"
	"gomodules.xyz/blobfs"
	shell "gomodules.xyz/go-sh"
	"k8s.io/klog/v2"
	"kmodules.xyz/go-containerregistry/name"
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
	data, err := ReadFromBucket(mgr.fs, img)
	if err != nil {
		s := ErrorToAPIStatus(err)
		data, _ = json.Marshal(s)
		switch s.Code {
		case http.StatusNotFound:
			err = mgr.submitScanRequest(img)
			if err != nil {
				klog.ErrorS(err, "failed to parse or get", "image", img)
				return nil, err
			}
		case http.StatusTooManyRequests:
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

	var resp trivy.BackendResponse
	err = trivy.JSON.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

const reportFileName = "report.json"

func ReadFromBucket(fs blobfs.Interface, img string) ([]byte, error) {
	ref, err := name.ParseOrExtractDigest(img)
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(context.TODO(), path.Join(ref.Registry, ref.Repository, ref.Digest, reportFileName))
}

func ExistsReport(fs blobfs.Interface, img string) (bool, error) {
	ref, err := name.ParseOrExtractDigest(img)
	if err != nil {
		return false, err
	}
	exists, err := fs.Exists(context.TODO(), path.Join(ref.Registry, ref.Repository, ref.Digest, reportFileName))
	if err != nil || !exists {
		return false, err
	}

	// If file exists, & it is more than 6 hours old, We consider it as if it doesn't exist.
	read, err := fs.ReadFile(context.TODO(), path.Join(ref.Registry, ref.Repository, ref.Digest, reportFileName))
	if err != nil {
		return false, err
	}
	var res trivy.BackendResponse
	err = trivy.JSON.Unmarshal(read, &res)
	if err != nil {
		return false, err
	}

	ver, err := getVersionInfo()
	if err != nil {
		return false, err
	}
	return !res.TrivyVersion.VulnerabilityDB.UpdatedAt.Before(ver.VulnerabilityDB.UpdatedAt.Time), nil
}

func UploadReport(fs blobfs.Interface, img string) error {
	rep, err := scan(img)
	if err != nil {
		return err
	}

	ver, err := getVersionInfo()
	if err != nil {
		return err
	}

	ref, err := name.ParseOrExtractDigest(img)
	if err != nil {
		return err
	}

	resp := trivy.BackendResponse{
		Report:       *rep,
		TrivyVersion: *ver,
		ImageDetails: trivy.ImageDetails{
			Name:       ref.Name,
			Tag:        ref.Tag,
			Digest:     ref.Digest,
			Visibility: trivy.ImageVisibilityPublic,
		},
	}
	marshaledResp, err := trivy.JSON.Marshal(&resp)
	if err != nil {
		return err
	}

	return fs.WriteFile(context.TODO(), path.Join(ref.Registry, ref.Repository, ref.Digest, reportFileName), marshaledResp)
}

// trivy image ubuntu --security-checks vuln --format json --quiet
func scan(img string) (*trivy.SingleReport, error) {
	sh := getNewShell()
	args := []any{
		"image",
		img,
		"--security-checks", "vuln",
		"--format", "json",
		// "--quiet",
	}
	out, err := sh.Command("trivy", args...).Output()
	if err != nil {
		return nil, err
	}

	var r trivy.SingleReport
	err = trivy.JSON.Unmarshal(out, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func getVersionInfo() (*trivy.Version, error) {
	sh := getNewShell()
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

func getNewShell() *shell.Session {
	sh := shell.NewSession()
	sh.SetDir("/tmp")

	sh.ShowCMD = true
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr
	return sh
}
