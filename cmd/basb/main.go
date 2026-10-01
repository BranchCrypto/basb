package main

import (
	"fmt"
	"os"

	"basb/internal/api"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "basb",
		Short: "Desktop sandbox audit tool — trusted ledger of agent system behavior",
	}

	var dataRoot string
	root.PersistentFlags().StringVar(&dataRoot, "data", "data", "session data root directory")

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run an agent inside a Windows Job Object sandbox and record events",
		RunE: func(cmd *cobra.Command, args []string) error {
			agent, _ := cmd.Flags().GetString("agent")
			workdir, _ := cmd.Flags().GetString("workdir")
			sessionID, _ := cmd.Flags().GetString("session")
			agentArgs, _ := cmd.Flags().GetStringSlice("arg")
			light, _ := cmd.Flags().GetBool("light")
			res, err := api.Run(api.RunOptions{
				DataRoot: dataRoot,
				Session:  sessionID,
				Agent:    agent,
				WorkDir:  workdir,
				Args:     agentArgs,
				Light:    light,
			})
			if res != nil {
				fmt.Fprintf(os.Stderr, "\nsession dir: %s\n", res.Dir)
			}
			return err
		},
	}
	runCmd.Flags().String("agent", "", "path to agent executable (required)")
	runCmd.Flags().String("workdir", "", "working directory for the agent")
	runCmd.Flags().String("session", "", "session id (default: timestamp)")
	runCmd.Flags().StringSlice("arg", nil, "arguments passed to the agent")
	runCmd.Flags().Bool("light", false, "skip slow firewall/tasks/services/defender snapshots")
	_ = runCmd.MarkFlagRequired("agent")

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show session timeline / summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, _ := cmd.Flags().GetString("session")
			types, _ := cmd.Flags().GetString("type")
			_, err := api.ShowSession(dataRoot, sessionID, types)
			return err
		},
	}
	showCmd.Flags().String("session", "", "session id (required)")
	showCmd.Flags().String("type", "", "filter types: shell,process,network|net,file|fs,credential|secret,sensitive|risk,… (comma-separated)")
	_ = showCmd.MarkFlagRequired("session")

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export an audit-pack zip",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, _ := cmd.Flags().GetString("session")
			out, _ := cmd.Flags().GetString("out")
			if err := api.ExportSession(dataRoot, sessionID, out); err != nil {
				return err
			}
			fmt.Println("exported:", out)
			return nil
		},
	}
	exportCmd.Flags().String("session", "", "session id (required)")
	exportCmd.Flags().String("out", "", "output zip path")
	_ = exportCmd.MarkFlagRequired("session")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := api.ListSessions(dataRoot)
			if err != nil {
				return err
			}
			if len(metas) == 0 {
				fmt.Println("no sessions")
				return nil
			}
			for _, m := range metas {
				code := "-"
				if m.ExitCode != nil {
					code = fmt.Sprintf("%d", *m.ExitCode)
				}
				fmt.Printf("%-20s  %-10s  exit=%s  %s\n", m.ID, m.Status, code, m.Agent)
			}
			return nil
		},
	}

	root.AddCommand(runCmd, showCmd, exportCmd, listCmd)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
