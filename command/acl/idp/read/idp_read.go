package idpread

import (
	"flag"
	"fmt"

	"github.com/hashicorp/consul/command/acl"
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

	showMeta bool
}

func (c *cmd) init() {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)

	c.flags.BoolVar(
		&c.showMeta,
		"meta",
		false,
		"Indicates that identity provider metadata such "+
			"as the content hash and raft indices should be shown for each entry.",
	)

	c.flags.StringVar(
		&c.name,
		"name",
		"",
		"The name of the identity provider to read.",
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

	idp, _, err := client.ACL().IdentityProviderRead(c.name, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading identity provider %q: %v", c.name, err))
		return 1
	} else if idp == nil {
		c.UI.Error(fmt.Sprintf("Identity provider not found with name %q", c.name))
		return 1
	}
	acl.PrintIdentityProvider(idp, c.UI, c.showMeta)
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Read an ACL Identity Provider"
const help = `
Usage: consul acl idp read -name NAME [options]

  This command will retrieve and print out the details of a single identity provider.

    Read:

        $ consul acl idp read -name "my-idp"
`
