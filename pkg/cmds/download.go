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
	"fmt"
	"time"

	"kubeops.dev/scanner/pkg/backend"

	"github.com/spf13/cobra"
	"gocloud.dev/gcerrors"
	"k8s.io/klog/v2"
)

func NewCmdDownload() *cobra.Command {
	var (
		addr = "this-is-nats.appscode.ninja:4222"
		img  = "postgres:14"
	)
	cmd := &cobra.Command{
		Use:               "download",
		Short:             "Download scan summary",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			nc, err := backend.NewConnection(addr, "")
			if err != nil {
				return err
			}

			data, err := backend.DownloadSummary(backend.NewBlobFS(), img)
			// gocloud.dev/gcerrors.NotFound (2)
			if err != nil {
				if gcerrors.Code(err) == gcerrors.NotFound {
					// submit scan request
					if _, err := nc.Request("scanner.queue.scan", []byte(img), 100*time.Millisecond); err != nil {
						klog.ErrorS(err, "failed submit scan request", "image", img)
					} else {
						klog.InfoS("submitted scan request", "image", img)
					}
				}
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}

	cmd.Flags().StringVar(&img, "image", img, "Image to scan (eg: ubuntu)")
	return cmd
}
