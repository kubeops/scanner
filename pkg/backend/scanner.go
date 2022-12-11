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
	"os"
	"path"
	"strings"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	_ "gocloud.dev/blob/s3blob"
	"gomodules.xyz/blobfs"
	shell "gomodules.xyz/go-sh"
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

func DownloadReport(fs blobfs.Interface, img string) ([]byte, error) {
	repo, digest, err := ParseReference(img)
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(context.TODO(), path.Join(repo, digest, "report.json"))
}

func DownloadSummary(fs blobfs.Interface, img string) ([]byte, error) {
	repo, digest, err := ParseReference(img)
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(context.TODO(), path.Join(repo, digest, "summary.json"))
}

func ExistsReport(fs blobfs.Interface, img string) (bool, error) {
	repo, digest, err := ParseReference(img)
	if err != nil {
		return false, err
	}
	return fs.Exists(context.TODO(), path.Join(repo, digest, "summary.json"))
}

func uploadVersionInfo(fs blobfs.Interface, repo, digest string) error {
	sh := shell.NewSession()
	sh.SetDir("/tmp")

	sh.ShowCMD = true
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr

	args := []any{
		"image",
		"version",
		"--format", "json",
	}
	out, err := sh.Command("trivy", args...).Output()
	if err != nil {
		return err
	}

	var r api.TrivyVersion
	err = json.Unmarshal(out, &r)
	if err != nil {
		return err
	}

	return fs.WriteFile(context.TODO(), path.Join(repo, digest, "trivy.json"), out)
}

func UploadReport(fs blobfs.Interface, img string) error {
	_, reportBytes, err := scan(img)
	if err != nil {
		return err
	}

	repo, digest, err := ParseReference(img)
	if err != nil {
		return err
	}

	err = fs.WriteFile(context.TODO(), path.Join(repo, digest, "report.json"), reportBytes)
	if err != nil {
		return err
	}

	//summary := api.Summary{
	//	SchemaVersion: report.SchemaVersion,
	//	ArtifactName:  report.ArtifactName,
	//	ArtifactType:  report.ArtifactType,
	//	Metadata:      report.Metadata,
	//	Results:       make([]api.SummaryResult, 0, len(report.Results)),
	//}
	//for _, r := range report.Results {
	//	stats := map[string]int{}
	//	for _, vul := range r.Vulnerabilities {
	//		stats[vul.Severity] = stats[vul.Severity] + 1
	//	}
	//	sr := api.SummaryResult{
	//		Target:          r.Target,
	//		Class:           r.Class,
	//		Type:            r.Type,
	//		Vulnerabilities: stats,
	//	}
	//	summary.Results = append(summary.Results, sr)
	//}
	//sBytes, err := json.Marshal(summary)
	//if err != nil {
	//	return err
	//}
	//err = fs.WriteFile(context.TODO(), path.Join(repo, digest, "summary.json"), sBytes)
	//if err != nil {
	//	return err
	//}

	return uploadVersionInfo(fs, repo, digest)
}

// trivy image ubuntu --security-checks vuln --format json --quiet
func scan(img string) (*api.SingleReport, []byte, error) {
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

	var r api.SingleReport
	err = json.Unmarshal(out, &r)
	if err != nil {
		return nil, nil, err
	}

	return &r, out, nil
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
