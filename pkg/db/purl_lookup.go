package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// purlMapTable is the sync-time normalized PURL index for a main advisory table.
func purlMapTable(tableName string) string {
	return tableName + "_purl_map"
}

// packageKeyFromPurl strips the @version (and anything after) from a PURL string.
func packageKeyFromPurl(purl string) string {
	if at := strings.Index(purl, "@"); at > 0 {
		return purl[:at]
	}
	return purl
}

func schemaUsesPurlMap(schema *Schema) bool {
	if schema == nil {
		return false
	}
	return schema.Name == "purl PM" || schema.Name == "purl OS"
}

// BuildPurlLookupTable expands each row's JSON purl array into an equality-
// searchable map table: (purl, pkg, src_rowid). Also drops the legacy
// idx_<table>_purl B-tree on the JSON blob, which cannot serve LIKE '%…%'.
func BuildPurlLookupTable(dbConn *sql.DB, tableName string) error {
	mapName := purlMapTable(tableName)

	if _, err := dbConn.Exec(fmt.Sprintf(`DROP INDEX IF EXISTS "idx_%s_purl"`, tableName)); err != nil {
		return fmt.Errorf("failed to drop legacy purl index: %w", err)
	}

	tx, err := dbConn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS "%s"`, mapName)); err != nil {
		return fmt.Errorf("failed to drop purl map %s: %w", mapName, err)
	}

	createSQL := fmt.Sprintf(
		`CREATE TABLE "%s" ("purl" TEXT NOT NULL, "pkg" TEXT NOT NULL, "src_rowid" INTEGER NOT NULL, PRIMARY KEY ("purl", "src_rowid"))`,
		mapName,
	)
	if _, err := tx.Exec(createSQL); err != nil {
		return fmt.Errorf("failed to create purl map %s: %w", mapName, err)
	}

	rows, err := tx.Query(fmt.Sprintf(`SELECT rowid, purl FROM "%s"`, tableName))
	if err != nil {
		return fmt.Errorf("failed to read %s for purl map: %w", tableName, err)
	}

	insertSQL := fmt.Sprintf(`INSERT OR IGNORE INTO "%s" ("purl", "pkg", "src_rowid") VALUES (?, ?, ?)`, mapName)
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = rows.Close()
		return err
	}

	for rows.Next() {
		var rowID int64
		var purlJSON sql.NullString
		if err := rows.Scan(&rowID, &purlJSON); err != nil {
			_ = stmt.Close()
			_ = rows.Close()
			return fmt.Errorf("failed to scan row for purl map: %w", err)
		}
		if !purlJSON.Valid || purlJSON.String == "" {
			continue
		}
		var purls []string
		if err := json.Unmarshal([]byte(purlJSON.String), &purls); err != nil {
			_ = stmt.Close()
			_ = rows.Close()
			return fmt.Errorf("failed to unmarshal purl JSON for rowid %d: %w", rowID, err)
		}
		for _, purl := range purls {
			if purl == "" {
				continue
			}
			if _, err := stmt.Exec(purl, packageKeyFromPurl(purl), rowID); err != nil {
				_ = stmt.Close()
				_ = rows.Close()
				return fmt.Errorf("failed to insert purl map row: %w", err)
			}
		}
	}
	if err := rows.Err(); err != nil {
		_ = stmt.Close()
		_ = rows.Close()
		return err
	}
	if err := stmt.Close(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	pkgIndex := fmt.Sprintf(`CREATE INDEX "idx_%s_pkg" ON "%s"("pkg")`, mapName, mapName)
	if _, err := tx.Exec(pkgIndex); err != nil {
		return fmt.Errorf("failed to create pkg index on %s: %w", mapName, err)
	}

	return tx.Commit()
}

func purlMapExists(dbConn *sql.DB, tableName string) (bool, error) {
	var name string
	err := dbConn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`,
		purlMapTable(tableName),
	).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// queryPurlRowsByMap loads advisory rows via the normalized map.
// When usePackage is true, match map.pkg (versionless / OS); otherwise map.purl.
func queryPurlRowsByMap(dbConn *sql.DB, tableName, key string, usePackage bool) (*sql.Rows, error) {
	mapName := purlMapTable(tableName)
	column := "purl"
	if usePackage {
		column = "pkg"
	}
	query := fmt.Sprintf(`
SELECT n.name, n.version, n.purl, n.cves, n.vulnerabilities
FROM "%s" n
INNER JOIN "%s" m ON m.src_rowid = n.rowid
WHERE m."%s" = ?`, tableName, mapName, column)
	return dbConn.Query(query, key)
}
