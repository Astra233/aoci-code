package textassets

import (
	"reflect"
	"testing"
)

// The memoized embedded manifest must be exactly what a fresh decode of the
// same bytes produces, and callers must never share one mutable value.
func TestReadManifestMemoMatchesFreshDecodeAndIsolatesCallers(t *testing.T) {
	fresh, err := readManifestFS(embeddedAssets)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifestMetadata(fresh); err != nil {
		t.Fatal(err)
	}
	first, err := ReadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, fresh) {
		t.Fatalf("memoized manifest differs from a fresh decode:\n%#v\n%#v", first, fresh)
	}

	first.OfficialLocales[0] = "xx-XX"
	first.Assets[0].ID = "tampered"
	second, err := ReadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, fresh) {
		t.Fatal("a caller's edits to its ReadManifest clone reached the next caller")
	}

	freshLoad, err := loadFS(embeddedAssets, DefaultLocale, ContractUIMessages)
	if err != nil {
		t.Fatal(err)
	}
	memoLoad, err := Load(DefaultLocale, ContractUIMessages)
	if err != nil {
		t.Fatal(err)
	}
	if memoLoad != freshLoad {
		t.Fatal("Load through the memoized manifest returned different bytes than a fresh decode")
	}
}

// RelocalizeMessageExact walks the official locales in manifest order from the
// once-decoded bundle; the answer has to be the one the manifest order gives.
func TestRelocalizeMessageExactFollowsManifestLocaleOrder(t *testing.T) {
	manifest, err := ReadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uiMessageCatalog(DefaultLocale); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(uiMessageLocales, manifest.OfficialLocales) {
		t.Fatalf("cached locale order %v differs from the manifest order %v", uiMessageLocales, manifest.OfficialLocales)
	}
	english, err := Message(DefaultLocale, "cli.short.init")
	if err != nil {
		t.Fatal(err)
	}
	chinese, err := Message(LegacyLocale, "cli.short.init")
	if err != nil {
		t.Fatal(err)
	}
	relocalized, found, err := RelocalizeMessageExact(LegacyLocale, english)
	if err != nil || !found || relocalized != chinese {
		t.Fatalf("relocalize %q: got %q found=%v err=%v, want %q", english, relocalized, found, err, chinese)
	}
	if _, found, err := RelocalizeMessageExact(LegacyLocale, "no catalog carries this sentence"); err != nil || found {
		t.Fatalf("an unknown value must not relocalize: found=%v err=%v", found, err)
	}
}
