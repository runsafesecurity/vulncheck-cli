// One-shot rebuild of *_purl_map tables for an existing offline data.db
// (avoids a full index re-download when profiling the sync-time map design).
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/vulncheck-oss/cli/pkg/db"
)

func main() {
	tables := []string{"npm", "ubuntu_purls", "alpine_purls", "pypi", "golang", "maven", "nuget", "cargo"}
	if len(os.Args) > 1 {
		tables = os.Args[1:]
	}

	dbConn, err := db.DB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		os.Exit(1)
	}

	for _, table := range tables {
		table = strings.TrimSpace(table)
		if table == "" {
			continue
		}
		fmt.Printf("building %s_purl_map …\n", table)
		if err := db.BuildPurlLookupTable(dbConn, table); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", table, err)
			os.Exit(1)
		}
		fmt.Printf("  done %s\n", table)
	}
}
