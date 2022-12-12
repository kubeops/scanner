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

package cmds

import (
	"encoding/json"
	"os"

	api "kubeops.dev/scanner/apis/scanner/v1alpha1"
	"kubeops.dev/scanner/apis/trivy"
	"kubeops.dev/scanner/pkg/controllers"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func NewCmdUploadReport() *cobra.Command {
	var (
		reportFile string
		trivyFile  string
		imageRef   string
	)
	cmd := &cobra.Command{
		Use:               "upload-report",
		Short:             "Convert trivy report to ImageScanReport and uploads to etcd",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return uploadReport(imageRef, trivyFile, reportFile)
		},
	}

	cmd.Flags().StringVar(&reportFile, "report-file", reportFile, "the path of the report.json file")
	cmd.Flags().StringVar(&trivyFile, "trivy-file", trivyFile, "the path which contains the trivy version related info")
	cmd.Flags().StringVar(&imageRef, "image", imageRef, "Image to scan (eg: ubuntu)")
	return cmd
}

func uploadReport(imageRef, trivyFile, reportFile string) error {
	kc, err := NewClient()
	if err != nil {
		return err
	}

	trivyInfo, err := readFile(trivyFile)
	if err != nil {
		return err
	}
	reportInfo, err := readFile(reportFile)
	if err != nil {
		return err
	}
	klog.Infof("%v %v \n", string(trivyInfo), string(reportInfo))

	// convert

	var actualReport trivy.SingleReport
	err = json.Unmarshal(reportInfo, &actualReport)
	if err != nil {
		return err
	}

	var ver trivy.Version
	err = json.Unmarshal(trivyInfo, &ver)
	if err != nil {
		return err
	}

	_, err = controllers.EnsureScanReport(kc, imageRef, actualReport, ver)
	return err
}

func readFile(filePath string) ([]byte, error) {
	// read the files
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		klog.Infof("Hey, The file in %v doesn't exist", filePath)
	}
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filePath)
}

func NewClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)

	ctrl.SetLogger(klogr.New())
	cfg := ctrl.GetConfigOrDie()
	cfg.QPS = 100
	cfg.Burst = 100

	mapper, err := apiutil.NewDynamicRESTMapper(cfg)
	if err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{
		Scheme: scheme,
		Mapper: mapper,
	})
}
