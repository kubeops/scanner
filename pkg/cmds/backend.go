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
	"context"

	"kubeops.dev/scanner/pkg/backend"

	"github.com/spf13/cobra"
)

func NewCmdBackend(ctx context.Context) *cobra.Command {
	var (
		addr     = "this-is-nats.appscode.ninja:4222"
		credFile string
	)
	cmd := &cobra.Command{
		Use:               "backend",
		Short:             "Scanner backend",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			nc, err := backend.NewConnection(addr, credFile)
			if err != nil {
				return err
			}
			defer nc.Drain() //nolint:errcheck

			opts := backend.DefaultOptions()
			opts.FS = backend.NewBlobFS()
			mgr := backend.New(nc, opts)
			if err := mgr.Start(ctx); err != nil {
				return err
			}

			<-ctx.Done()
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "nats-addr", addr, "NATS serve address")
	cmd.Flags().StringVar(&credFile, "nats-credential-file", credFile, "PATH to NATS credential file")
	return cmd
}
