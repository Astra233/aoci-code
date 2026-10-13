package dbevidence

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// mysqlServerVersion is the numeric prefix of VERSION(). MySQL reports
// major.minor.patch first and may append build commentary ("5.7.44-log",
// "8.0.16-0ubuntu0.20.04.1", "8.0.32-debug") that never changes the catalog
// shape.
type mysqlServerVersion struct{ Major, Minor, Patch int }

// The catalog profile thresholds. Each one names the first MySQL release whose
// information_schema carries the fact the 8.x inventory reads; an older server
// answers the same canonical shape from the projection it can run.
var (
	// COLUMNS.GENERATION_EXPRESSION arrived with generated columns in 5.7.6;
	// an older server cannot answer the shared columns query at all.
	mysqlMinimumVersion = mysqlServerVersion{5, 7, 6}
	// STATISTICS.IS_VISIBLE arrived with invisible indexes in 8.0.0; before it
	// every index is visible, so 'YES' is the exact fact.
	mysqlIndexVisibilityVersion = mysqlServerVersion{8, 0, 0}
	// STATISTICS.EXPRESSION arrived with functional indexes in 8.0.13; before
	// it every index element is a column, so NULL is the exact fact.
	mysqlIndexExpressionVersion = mysqlServerVersion{8, 0, 13}
	// information_schema.CHECK_CONSTRAINTS arrived with enforced CHECK
	// constraints in 8.0.16. An older server parses the CHECK clause and
	// stores nothing, so an empty check list is the exact fact, not a loss.
	mysqlCheckConstraintVersion = mysqlServerVersion{8, 0, 16}
)

var (
	mysqlVersionPattern      = regexp.MustCompile(`^([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})(?:[^0-9]|$)`)
	errMySQLVersionMalformed = errors.New("mysql server version is not major.minor.patch")
	errMySQLVariant          = errors.New("mysql server version names an unsupported engine variant")
)

// parseMySQLServerVersion reads VERSION() as the server reported it. MariaDB
// uses the same channel ("10.11.6-MariaDB-1:10.11.6+maria~ubu2204", or
// "5.5.5-10.4.13-MariaDB" behind its replication prefix) but has its own
// catalog, so it is refused as a variant rather than read as the MySQL release
// whose number it borrows. A string without a leading major.minor.patch is
// refused as malformed: the collector cannot prove which catalog shape such a
// server has.
func parseMySQLServerVersion(reported string) (mysqlServerVersion, error) {
	text := normalizeCatalogText(reported)
	if strings.Contains(strings.ToLower(text), "mariadb") {
		return mysqlServerVersion{}, errMySQLVariant
	}
	match := mysqlVersionPattern.FindStringSubmatch(text)
	if match == nil {
		return mysqlServerVersion{}, errMySQLVersionMalformed
	}
	var parts [3]int
	for index, field := range match[1:4] {
		value, err := strconv.Atoi(field)
		if err != nil {
			return mysqlServerVersion{}, errMySQLVersionMalformed
		}
		parts[index] = value
	}
	return mysqlServerVersion{Major: parts[0], Minor: parts[1], Patch: parts[2]}, nil
}

func (version mysqlServerVersion) atLeast(floor mysqlServerVersion) bool {
	if version.Major != floor.Major {
		return version.Major > floor.Major
	}
	if version.Minor != floor.Minor {
		return version.Minor > floor.Minor
	}
	return version.Patch >= floor.Patch
}

// mysqlCatalogProfile selects the two version-gated queries. Everything it
// does not name is shared by every supported release.
type mysqlCatalogProfile struct {
	checks     bool   // information_schema.CHECK_CONSTRAINTS exists
	indexesSQL string // the STATISTICS projection this server can answer
}

// mysqlCatalogProfileFor refuses, in the same vocabulary the openGauss
// collector uses for an unsupported server, what the inventory cannot describe
// exactly: MariaDB (mysql_variant) and a release below 5.7.6 or without a
// readable version (mysql_version).
func mysqlCatalogProfileFor(reported string) (mysqlCatalogProfile, error) {
	version, err := parseMySQLServerVersion(reported)
	if errors.Is(err, errMySQLVariant) {
		return mysqlCatalogProfile{}, &unsupportedCatalogFeature{feature: "mysql_variant"}
	}
	if err != nil || !version.atLeast(mysqlMinimumVersion) {
		return mysqlCatalogProfile{}, &unsupportedCatalogFeature{feature: "mysql_version"}
	}
	profile := mysqlCatalogProfile{checks: version.atLeast(mysqlCheckConstraintVersion), indexesSQL: mysqlIndexesSQL}
	switch {
	case !version.atLeast(mysqlIndexVisibilityVersion):
		profile.indexesSQL = mysqlIndexesPre80SQL
	case !version.atLeast(mysqlIndexExpressionVersion):
		profile.indexesSQL = mysqlIndexesPre8013SQL
	}
	return profile, nil
}
