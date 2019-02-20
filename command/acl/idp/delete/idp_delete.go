package idpdelete

import (
	"flag"
	"fmt"

	"github.com/hashicorp/consul/command/flags"
	"github.com/mitchellh/cli"
)

func New(ui cli.Ui) *cmd {
	c := &cmd{UI: ui}
	c.init()
	return c
}

type cmd struct {
	UI    cli.Ui
	flags *flag.FlagSet
	http  *flags.HTTPFlags
	help  string

	name string
}

func (c *cmd) init() {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)

	c.flags.StringVar(
		&c.name,
		"name",
		"",
		"The name of the identity provider to delete.",
	)

	c.http = &flags.HTTPFlags{}
	flags.Merge(c.flags, c.http.ClientFlags())
	flags.Merge(c.flags, c.http.ServerFlags())
	c.help = flags.Usage(help, c.flags)
}

func (c *cmd) Run(args []string) int {
	if err := c.flags.Parse(args); err != nil {
		return 1
	}

	if c.name == "" {
		c.UI.Error(fmt.Sprintf("Must specify the -name parameter"))
		return 1
	}

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	if _, err := client.ACL().IdentityProviderDelete(c.name, nil); err != nil {
		c.UI.Error(fmt.Sprintf("Error deleting identity provider %q: %v", c.name, err))
		return 1
	}

	c.UI.Info(fmt.Sprintf("Identity provider %q deleted successfully", c.name))
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Delete an ACL Identity Provider"
const help = `
Usage: consul acl idp delete -name NAME [options]

    Deletes an ACL identity provider by name.

    Delete by name:

        $ consul acl idp delete -name "my-idp"
`
