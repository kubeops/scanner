package cmds

import (
	"kubeops.dev/scanner/pkg/scanner"

	"github.com/spf13/cobra"
)

func NewCmdScanImage() *cobra.Command {
	var img string
	cmd := &cobra.Command{
		Use:               "scan",
		Short:             "Scan and upload a docker image",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return scanner.UploadReport(scanner.NewBlobFS(), img)
		},
	}

	cmd.Flags().StringVar(&img, "image", img, "Image to scan (eg: ubuntu)")
	return cmd
}
