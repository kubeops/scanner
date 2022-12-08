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
	"kubeops.dev/scanner/apis/cves/v1alpha1"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
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
			return uploadReport()
		},
	}

	cmd.Flags().StringVar(&reportFile, "report-file", reportFile, "Image to scan (eg: ubuntu)")
	cmd.Flags().StringVar(&trivyFile, "trivy-file", trivyFile, "Image to scan (eg: ubuntu)")
	cmd.Flags().StringVar(&imageRef, "image", imageRef, "Image to scan (eg: ubuntu)")
	return cmd
}

func uploadReport() error {
	/* kc */ _, err := NewClient()
	if err != nil {
		return err
	}

	// convert

	// upload

	return nil
}

func NewClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

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
		//Opts: client.WarningHandlerOptions{
		//	SuppressWarnings:   false,
		//	AllowDuplicateLogs: false,
		//},
	})
}
