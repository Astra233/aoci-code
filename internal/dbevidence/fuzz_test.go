// Native fuzz target for the openGauss DSN reader the Evidence collector
// trusts: ParseConfigStrict from the patched connector, reached through the
// same first-party opener production uses. Run it with
//
//	go test -run '^$' -fuzz '^FuzzParseConfigStrict$' -fuzztime=30s ./internal/dbevidence
//
// or every target through `make fuzz-smoke`.
package dbevidence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	opengauss "gitcode.com/opengauss/openGauss-connector-go-pq"
)

// writeFuzzRootCertificate writes a self-signed CA so the sslrootcert path of
// the strict parser is reachable with a certificate it can actually load.
func writeFuzzRootCertificate(f *testing.F, path string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AOCI fuzz CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		f.Fatal(err)
	}
}

func isNumericLoopback(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// fuzzDSNSettings reads the DSN the way the connector does, only to find an
// sslrootcert value; the vendored reader panics on some malformed strings
// (see parseOpenGaussDSN), which the boundary under test turns into a refusal.
func fuzzDSNSettings(dsn string) (settings map[string]string) {
	defer func() {
		if recover() != nil {
			settings = nil
		}
	}()
	parsed, err := opengauss.ParseURLToMap(dsn)
	if err != nil {
		return nil
	}
	return parsed
}

// FuzzParseConfigStrict pins the connection-string boundary through the
// first-party entry production uses (parseOpenGaussDSN wrapping the connector's
// ParseConfigStrict): no panic on any DSN; the first-party opener admits
// exactly what the parser admits; an admitted configuration never carries a
// multi-host fallback, never speaks plaintext TCP to anything but a numeric
// loopback address, carries a verify-full TLS configuration (hostname
// verified, TLS 1.2 floor) everywhere else, and never picks up ambient logger,
// timeout, or runtime parameters.
func FuzzParseConfigStrict(f *testing.F) {
	fixtures := f.TempDir()
	caPath := filepath.Join(fixtures, "ca.pem")
	writeFuzzRootCertificate(f, caPath)
	bogusPath := filepath.Join(fixtures, "not-a-certificate.txt")
	if err := os.WriteFile(bogusPath, []byte("not pem\n"), 0o600); err != nil {
		f.Fatal(err)
	}

	for _, seed := range []string{
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=verify-full",
		"host=localhost port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=127.0.0.1 port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=::1 port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=/tmp port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=/tmp port=5432 dbname=app user=reader password=secret sslmode=verify-full",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=allow",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=prefer",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=require",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=verify-ca",
		"host=localhost,127.0.0.1 port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=localhost port=5432,5433 dbname=app user=reader password=secret sslmode=disable",
		"host=127.0.0.1,127.0.0.2 port=5432 dbname=app user=reader password=secret sslmode=disable",
		"port=5432 dbname=app user=reader password=secret sslmode=disable",
		"host=localhost dbname=app user=reader password=secret sslmode=disable",
		"host=localhost port=5432 user=reader password=secret sslmode=disable",
		"host=localhost port=5432 dbname=app password=secret sslmode=disable",
		"host=localhost port=5432 dbname=app user=reader sslmode=disable",
		"host=localhost port=5432 dbname=app user=reader password=secret",
		"host=localhost port=5432 dbname=app user=reader password=secret sslmode=disable service=forbidden",
		"host=localhost port=5432 dbname=app user=reader password=secret sslmode=disable loggerLevel=debug",
		"host=localhost port=5432 dbname=app user=reader password=secret sslmode=disable connect_timeout=5",
		"host=localhost port=5432 dbname=app user=reader password=secret sslmode=disable search_path=x",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=verify-full sslrootcert=relative-ca.pem",
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=verify-full sslrootcert=" + caPath,
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=verify-full sslrootcert=" + bogusPath,
		"host=db.example.test port=5432 dbname=app user=reader password=secret sslmode=verify-full application_name=aoci",
		"host='db.example.test' port='5432' dbname='app' user='reader' password='se cret' sslmode='verify-full'",
		"host=db.example.test port=5432 dbname=app user=reader password='unterminated sslmode=verify-full",
		"host=db.example.test port=5432 dbname=app user=reader password=sec\\'ret sslmode=verify-full",
		"postgres://reader:secret@127.0.0.1:1/app",
		"postgres://reader:secret@db.example.test:5432/app?sslmode=disable",
		"postgres://reader:secret@db.example.test:5432/app?sslmode=require",
		"postgres://reader:secret@127.0.0.1:1/app?sslmode=disable&loggerLevel=debug",
		"postgres://reader:secret@127.0.0.1:1/app?sslmode=disable&service=aoci",
		"opengauss://reader:secret@127.0.0.1:1/app?sslmode=disable",
		"postgresql://reader:secret@[::1]:5432/app?sslmode=disable",
		"postgres://reader:secret@db.example.test:5432/app?sslmode=verify-full&sslrootcert=" + caPath,
		"postgres://reader:secret@db.example.test:5432/app?sslmode=verify-full&application_name=aoci",
		"postgres://reader:secret@host1,host2:5432/app?sslmode=verify-full",
		"postgres://reader:secret@db.example.test:5432,5433/app?sslmode=verify-full",
		"mogdb://reader:secret@127.0.0.1:5432/app?sslmode=disable",
		"https://reader:secret@127.0.0.1:5432/app?sslmode=disable",
		"POSTGRES://reader:secret@127.0.0.1:1/app?sslmode=disable",
		"postgres://reader:secret@127.0.0.1:99999/app?sslmode=disable",
		"postgres://reader:secret@127.0.0.1:0/app?sslmode=disable",
		"postgres://reader:secret@localhost:5432/app?sslmode=disable",
		"postgres://reader:secret@127.1:5432/app?sslmode=disable",
		"postgres://reader:secret@0:5432/app?sslmode=disable",
		"postgres://reader:secret@127.0.0.1:5432/app?sslmode=verify-full",
		"postgres://reader:secret@[::ffff:127.0.0.1]:5432/app?sslmode=disable",
		"postgres://reader:secret@%31%32%37.0.0.1:5432/app?sslmode=disable",
		"postgres://reader:secret@127.0.0.1:5432/app?sslmode=disable&sslmode=verify-full",
		"postgres://reader:secret@127.0.0.1:5432/app?sslmode=disable&host=db.example.test",
		"postgres://reader:secret@127.0.0.1:5432/app?sslmode=disable&port=5433,5434",
		"", " ", "=", "host=", "host==x", "host=a b", "a=b c=d",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, dsn string) {
		// A relative sslrootcert is refused before any file is opened; an absolute
		// one outside the fixtures would make the parser read an arbitrary file.
		if root, ok := fuzzDSNSettings(dsn)["sslrootcert"]; ok && filepath.IsAbs(root) && root != caPath && root != bogusPath {
			t.Skip("sslrootcert outside the fixture files would read an arbitrary file")
		}

		config, err := parseOpenGaussDSN(dsn)
		database, openErr := openOpenGaussDatabase(dsn, func(string) string { return "unsafe" })
		if database != nil {
			database.Close()
		}
		if (err == nil) != (openErr == nil) {
			t.Fatalf("strict parser and first-party opener disagree on %q: %v vs %v", dsn, err, openErr)
		}
		if err != nil {
			if config != nil {
				t.Fatalf("refused %q but returned a configuration", dsn)
			}
			if err.Error() == "" {
				t.Fatalf("refused %q without a reason", dsn)
			}
			return
		}
		if config == nil {
			t.Fatalf("admitted %q without a configuration", dsn)
		}
		if len(config.Fallbacks) != 0 {
			t.Fatalf("admitted %q with %d fallback connections", dsn, len(config.Fallbacks))
		}
		if strings.Contains(config.Host, ",") {
			t.Fatalf("admitted %q with a multi-host spelling %q", dsn, config.Host)
		}
		if config.Database == "" || config.User == "" || config.Password == "" {
			t.Fatalf("admitted %q with an implicit database, user, or password", dsn)
		}
		if config.Logger != nil || config.LogLevel != 0 || config.ConnectTimeout != 0 {
			t.Fatalf("admitted %q with ambient logger or timeout settings", dsn)
		}
		for key := range config.RuntimeParams {
			if key != "application_name" {
				t.Fatalf("admitted %q with runtime parameter %q", dsn, key)
			}
		}
		network, _ := opengauss.NetworkAddress(config.Host, config.Port)
		switch {
		case network == "unix":
			if config.TLSConfig != nil {
				t.Fatalf("admitted %q with TLS over a Unix socket", dsn)
			}
		case config.TLSConfig == nil:
			if !isNumericLoopback(config.Host) {
				t.Fatalf("admitted %q: plaintext TCP to non-loopback host %q", dsn, config.Host)
			}
		default:
			tlsConfig := config.TLSConfig
			if tlsConfig.InsecureSkipVerify || tlsConfig.VerifyPeerCertificate != nil ||
				tlsConfig.ServerName != config.Host || tlsConfig.MinVersion != tls.VersionTLS12 {
				t.Fatalf("admitted %q with a TLS configuration weaker than verify-full: %+v", dsn, tlsConfig)
			}
		}
	})
}
