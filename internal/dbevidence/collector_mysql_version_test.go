package dbevidence

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseMySQLServerVersionReadsTheNumericPrefixAndRefusesVariants(t *testing.T) {
	for _, test := range []struct {
		reported string
		want     mysqlServerVersion
		err      error
	}{
		{"8.4.3", mysqlServerVersion{8, 4, 3}, nil},
		{"8.4.11", mysqlServerVersion{8, 4, 11}, nil},
		{"5.7.44", mysqlServerVersion{5, 7, 44}, nil},
		{"5.7.44-log", mysqlServerVersion{5, 7, 44}, nil},
		{"5.7.44-0ubuntu0.18.04.1-log", mysqlServerVersion{5, 7, 44}, nil},
		{"8.0.16-0ubuntu0.20.04.1", mysqlServerVersion{8, 0, 16}, nil},
		{"8.0.35-27", mysqlServerVersion{8, 0, 35}, nil},
		{"8.0.32-debug", mysqlServerVersion{8, 0, 32}, nil},
		{"  8.0.16\r\n", mysqlServerVersion{8, 0, 16}, nil},
		{"10.11.6-MariaDB-1:10.11.6+maria~ubu2204", mysqlServerVersion{}, errMySQLVariant},
		{"5.5.5-10.4.13-MariaDB-1:10.4.13+maria~focal", mysqlServerVersion{}, errMySQLVariant},
		{"11.4.2-MariaDB", mysqlServerVersion{}, errMySQLVariant},
		{"", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"8", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"8.0", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"8.0.", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"8.0.x", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"v8.0.16", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"mysql 8.0.16", mysqlServerVersion{}, errMySQLVersionMalformed},
		{"8.0.9999999999", mysqlServerVersion{}, errMySQLVersionMalformed},
	} {
		got, err := parseMySQLServerVersion(test.reported)
		if got != test.want || !errors.Is(err, test.err) || (err == nil) != (test.err == nil) {
			t.Errorf("parseMySQLServerVersion(%q) = %+v, %v; want %+v, %v", test.reported, got, err, test.want, test.err)
		}
	}
}

func TestMySQLServerVersionOrdersByMajorMinorPatch(t *testing.T) {
	for _, test := range []struct {
		version, floor mysqlServerVersion
		want           bool
	}{
		{mysqlServerVersion{5, 7, 5}, mysqlMinimumVersion, false},
		{mysqlServerVersion{5, 7, 6}, mysqlMinimumVersion, true},
		{mysqlServerVersion{5, 6, 51}, mysqlMinimumVersion, false},
		{mysqlServerVersion{5, 8, 0}, mysqlMinimumVersion, true},
		{mysqlServerVersion{7, 9, 99}, mysqlIndexVisibilityVersion, false},
		{mysqlServerVersion{8, 0, 0}, mysqlIndexVisibilityVersion, true},
		{mysqlServerVersion{8, 0, 12}, mysqlIndexExpressionVersion, false},
		{mysqlServerVersion{8, 0, 13}, mysqlIndexExpressionVersion, true},
		{mysqlServerVersion{8, 0, 15}, mysqlCheckConstraintVersion, false},
		{mysqlServerVersion{8, 0, 16}, mysqlCheckConstraintVersion, true},
		{mysqlServerVersion{8, 1, 0}, mysqlCheckConstraintVersion, true},
		{mysqlServerVersion{9, 0, 0}, mysqlCheckConstraintVersion, true},
	} {
		if got := test.version.atLeast(test.floor); got != test.want {
			t.Errorf("%+v.atLeast(%+v) = %t, want %t", test.version, test.floor, got, test.want)
		}
	}
}

func TestMySQLCatalogProfileFollowsTheServerVersion(t *testing.T) {
	for _, test := range []struct {
		reported   string
		checks     bool
		indexesSQL string
		feature    string
	}{
		{reported: "5.6.51", feature: "mysql_version"},
		{reported: "5.7.5", feature: "mysql_version"},
		{reported: "", feature: "mysql_version"},
		{reported: "8.0.mysql_aurora", feature: "mysql_version"},
		{reported: "10.11.6-MariaDB-1:10.11.6+maria~ubu2204", feature: "mysql_variant"},
		{reported: "5.7.6", checks: false, indexesSQL: mysqlIndexesPre80SQL},
		{reported: "5.7.44-log", checks: false, indexesSQL: mysqlIndexesPre80SQL},
		{reported: "8.0.0", checks: false, indexesSQL: mysqlIndexesPre8013SQL},
		{reported: "8.0.12", checks: false, indexesSQL: mysqlIndexesPre8013SQL},
		{reported: "8.0.13", checks: false, indexesSQL: mysqlIndexesSQL},
		{reported: "8.0.15", checks: false, indexesSQL: mysqlIndexesSQL},
		{reported: "8.0.16-0ubuntu0.20.04.1", checks: true, indexesSQL: mysqlIndexesSQL},
		{reported: "8.4.11", checks: true, indexesSQL: mysqlIndexesSQL},
		{reported: "9.1.0", checks: true, indexesSQL: mysqlIndexesSQL},
	} {
		profile, err := mysqlCatalogProfileFor(test.reported)
		if test.feature != "" {
			var unsupported *unsupportedCatalogFeature
			if !errors.As(err, &unsupported) || unsupported.feature != test.feature {
				t.Errorf("mysqlCatalogProfileFor(%q) err = %v, want unsupported %s", test.reported, err, test.feature)
			}
			continue
		}
		if err != nil || profile.checks != test.checks || profile.indexesSQL != test.indexesSQL {
			t.Errorf("mysqlCatalogProfileFor(%q) = {checks:%t indexes:%q}, %v; want {checks:%t indexes:%q}", test.reported, profile.checks, profile.indexesSQL, err, test.checks, test.indexesSQL)
		}
	}
}

func mysqlMockSnapshot(t *testing.T, version string) (*mockCatalogState, SourceManifest, Snapshot, map[string][]byte, error) {
	t.Helper()
	registerMockCatalogDriver.Do(func() { sql.Register("aoci_mock_catalog", mockCatalogDriver{}) })
	state := &mockCatalogState{engine: EngineMySQL, mysqlVersion: version}
	activeMockCatalogState = state
	database, _ := sql.Open("aoci_mock_catalog", "credential_sentinel")
	collector := newCollectorForTest(func(string) string { return "reader:credential_sentinel@tcp(secret-host)/aoci_test" }, func(string, string) (*sql.DB, error) { return database, nil })
	source := SourceConfig{SourceID: "primary", Engine: EngineMySQL, Database: "aoci_test", Namespaces: []string{"aoci_test"}, CredentialEnv: "AOCI_DB_PRIMARY_DSN", Enabled: true}
	manifest, snapshot, files, err := collector.Snapshot(context.Background(), source)
	return state, manifest, snapshot, files, err
}

func TestMySQLCollectorGatesTheCheckAndIndexQueriesByServerVersion(t *testing.T) {
	for _, test := range []struct {
		version    string
		checks     bool
		indexesSQL string
		fragments  []string
	}{
		{"5.7.44-log", false, mysqlIndexesPre80SQL, []string{`"checks": []`, `"visible": true`, `"prefix_length": 12`}},
		{"8.0.11", false, mysqlIndexesPre8013SQL, []string{`"checks": []`, `"visible": false`, `"prefix_length": 12`}},
		{"8.0.16", true, mysqlIndexesSQL, []string{`"checks": []`, `"visible": false`, `"prefix_length": 12`}},
		{"8.4.11", true, mysqlIndexesSQL, []string{`"checks": []`, `"visible": false`, `"prefix_length": 12`}},
	} {
		t.Run(test.version, func(t *testing.T) {
			state, manifest, snapshot, files, err := mysqlMockSnapshot(t, test.version)
			if err != nil || manifest.ServerVersion != test.version || len(snapshot.Tables) != 1 {
				t.Fatalf("mysql %s collection failed: manifest=%+v err=%v", test.version, manifest, err)
			}
			if slices.Contains(state.queries, mysqlChecksSQL) != test.checks {
				t.Fatalf("mysql %s ran the CHECK_CONSTRAINTS query: %t, want %t", test.version, !test.checks, test.checks)
			}
			for _, candidate := range []string{mysqlIndexesSQL, mysqlIndexesPre8013SQL, mysqlIndexesPre80SQL} {
				if slices.Contains(state.queries, candidate) != (candidate == test.indexesSQL) {
					t.Fatalf("mysql %s selected the wrong STATISTICS projection:\n%s", test.version, strings.Join(state.queries, "\n---\n"))
				}
			}
			data := string(files[snapshot.Tables[0].ObjectRef])
			for _, fragment := range test.fragments {
				if !strings.Contains(data, fragment) {
					t.Fatalf("mysql %s evidence omitted %q:\n%s", test.version, fragment, data)
				}
			}
		})
	}
}

func TestMySQLCollectorRejectsUnsupportedServersBeforeAnyTableQuery(t *testing.T) {
	for _, test := range []struct {
		name, version, op string
	}{
		{"below_5_7_6", "5.7.5", "catalog_query_facts_mysql_version"},
		{"5_6", "5.6.51-log", "catalog_query_facts_mysql_version"},
		// Whitespace trims to nothing; the mock reads "" as "default 8.4.0".
		{"unreadable", " \n", "catalog_query_facts_mysql_version"},
		{"no_patch", "8.0", "catalog_query_facts_mysql_version"},
		{"mariadb", "10.11.6-MariaDB-1:10.11.6+maria~ubu2204", "catalog_query_facts_mysql_variant"},
		{"mariadb_replication_prefix", "5.5.5-10.4.13-MariaDB-1:10.4.13+maria~focal", "catalog_query_facts_mysql_variant"},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, _, _, files, err := mysqlMockSnapshot(t, test.version)
			var sourceErr *SourceError
			if !errors.As(err, &sourceErr) || sourceErr.Code != "unsupported_catalog_feature" || sourceErr.Op != test.op || sourceErr.SourceID != "primary" {
				t.Fatalf("unsupported MySQL server %q was not rejected stably: %v", test.version, err)
			}
			if len(files) != 0 || !slices.Equal(state.queries, []string{mysqlFactsSQL}) {
				t.Fatalf("unsupported MySQL server %q was queried past the facts: files=%d queries=%d", test.version, len(files), len(state.queries))
			}
			if strings.Contains(err.Error(), "secret-host") || strings.Contains(err.Error(), "credential_sentinel") {
				t.Fatalf("refusal leaked connection material: %v", err)
			}
		})
	}
}
