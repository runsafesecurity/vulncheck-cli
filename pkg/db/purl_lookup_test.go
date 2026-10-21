package db

import (
	"testing"

	"github.com/package-url/packageurl-go"
)

func TestPurlLookupMatchesLegacyLike(t *testing.T) {
	setupPurlTable(t)
	setupPurlAmbiguousVersions(t)

	if err := BuildPurlLookupTable(testDB, "npm"); err != nil {
		t.Fatalf("BuildPurlLookupTable: %v", err)
	}

	cases := []packageurl.PackageURL{
		mustParsePurl("pkg:npm/express@4.17.1"),
		mustParsePurl("pkg:npm/express"),
		mustParsePurl("pkg:npm/foo@1.0.1"),
		mustParsePurl("pkg:npm/foo@1.0.10"),
		mustParsePurl("pkg:npm/nonexistent@1.0.0"),
	}

	for _, instance := range cases {
		withMap, _, err := PURLSearch("npm", instance)
		if err != nil {
			t.Fatalf("with map: %v", err)
		}

		if _, err := testDB.Exec(`DROP TABLE npm_purl_map`); err != nil {
			t.Fatalf("drop map: %v", err)
		}
		legacy, _, err := PURLSearch("npm", instance)
		if err != nil {
			t.Fatalf("legacy: %v", err)
		}
		if err := BuildPurlLookupTable(testDB, "npm"); err != nil {
			t.Fatalf("rebuild map: %v", err)
		}

		if len(withMap) != len(legacy) {
			t.Fatalf("%s: map hits %d, legacy %d", instance.String(), len(withMap), len(legacy))
		}
		if len(legacy) == 0 {
			continue
		}
		if withMap[0].Version != legacy[0].Version {
			t.Errorf("%s: version map=%s legacy=%s", instance.String(), withMap[0].Version, legacy[0].Version)
		}
	}
}

func TestPurlLookupOSMatchesLegacy(t *testing.T) {
	setupAlpinePurlsTable(t)
	if err := BuildPurlLookupTable(testDB, "alpine_purls"); err != nil {
		t.Fatalf("BuildPurlLookupTable: %v", err)
	}

	instance := mustParsePurl("pkg:apk/alpine/musl@1.1.22-r2?arch=x86_64&distro=alpine-3.10.0")
	withMap, _, err := PURLSearch("alpine-purls", instance)
	if err != nil {
		t.Fatalf("with map: %v", err)
	}

	if _, err := testDB.Exec(`DROP TABLE alpine_purls_purl_map`); err != nil {
		t.Fatalf("drop map: %v", err)
	}
	legacy, _, err := PURLSearch("alpine-purls", instance)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}

	if len(withMap) != len(legacy) {
		t.Fatalf("map entries %d legacy %d", len(withMap), len(legacy))
	}
	if len(legacy) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(legacy))
	}
	if len(withMap[0].Vulnerabilities) != len(legacy[0].Vulnerabilities) {
		t.Fatalf("vuln count map=%d legacy=%d", len(withMap[0].Vulnerabilities), len(legacy[0].Vulnerabilities))
	}
}
