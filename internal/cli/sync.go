package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Farzin312/waypost/internal/syncer"
)

func runSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root directory")
	apply := fs.Bool("apply", false, "apply safe drift updates and refresh the frozen lock")
	check := fs.Bool("check", false, "exit non-zero if actionable drift remains")
	offline := fs.Bool("offline", false, "restrict remote preset resolution to verified local cache")
	ref := fs.String("ref", "", "read-only committed Git snapshot")
	format := fs.String("format", "text", "output format: text or json")
	if err := parseCommandFlags(fs, args, stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "waypost sync: %v\n", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "waypost sync: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *apply && *ref != "" {
		fmt.Fprintln(stderr, "waypost sync: --ref is read-only")
		return 2
	}
	if *apply && *check {
		fmt.Fprintln(stderr, "waypost sync: --check and --apply are mutually exclusive")
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "waypost sync: invalid format %q\n", *format)
		return 2
	}
	report, err := syncer.Run(*dir, syncer.Options{Apply: *apply, Offline: *offline, Ref: *ref})
	if err != nil {
		fmt.Fprintf(stderr, "waypost sync: %v\n", err)
		return 1
	}
	if *format == "json" {
		if err := writeJSON(stdout, report); err != nil {
			fmt.Fprintf(stderr, "waypost sync: %v\n", err)
			return 1
		}
	} else {
		for _, item := range report.Items {
			hint := item.Hint
			if item.Applied {
				hint = "applied"
			}
			fmt.Fprintf(stdout, "%s: %s (%s)\n", item.Kind, item.Detail, hint)
		}
		if report.LockRefreshed {
			fmt.Fprintln(stdout, "Refreshed .waypost.lock.")
		}
		if len(report.Items) == 0 {
			fmt.Fprintln(stdout, "Waypost sync: clean")
		}
	}
	if (*apply || *check) && report.Pending() {
		return 1
	}
	return 0
}
