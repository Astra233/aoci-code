package cli

import (
	"testing"

	"github.com/aoci-spec/aoci-code/internal/testkit"
	"github.com/spf13/cobra"
)

// Locks: every visible command in the tree has a localized short description.
// The mapping from command path to message key is hand-kept, so a command
// registered without an entry rendered its package-init English Short under
// every locale; `aoci scope budget` listed its subcommands in English on a
// zh-CN repository that way.
func TestEveryVisibleCommandShortIsLocalized(t *testing.T) {
	// Registered commands are package-level singletons shared by every root,
	// so the English baseline is collected first and the same objects are then
	// relocalized under zh-CN.
	testkit.PinLocale(t, "en-US")
	english := map[string]string{}
	var collect func(*cobra.Command)
	collect = func(command *cobra.Command) {
		english[command.CommandPath()] = command.Short
		for _, child := range command.Commands() {
			collect(child)
		}
	}
	collect(newRootCmdLocalized())
	testkit.PinLocale(t, "zh-CN")
	root := newRootCmdLocalized()
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		path := command.CommandPath()
		if !command.Hidden && path != "aoci" {
			_, mapped := commandShortMessages[path]
			_, rendered := commandShortRenderers[path]
			if !mapped && !rendered {
				t.Errorf("%q has no localized short description entry", path)
			} else if command.Short == english[path] || command.Short == "" {
				t.Errorf("%q short description is not localized under zh-CN: %q", path, command.Short)
			}
		}
		for _, child := range command.Commands() {
			visit(child)
		}
	}
	visit(root)
}

func newRootCmdLocalized() *cobra.Command {
	root := newRootCmd()
	refreshCommandLocalization(root)
	return root
}
