package cmd

import (
	"fmt"
	"os"

	"github.com/luthersystems/aws-cred-setup/run"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Sets up a user for the first time.",
	Long:  `This currently configures MFA on a new AWS user.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := run.MFASetup()
		if err != nil {
			fmt.Printf("MFA setup failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
