package rolebindingrulelist

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

	idpName string

	showMeta bool
}

func (c *cmd) init() {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)

	c.flags.BoolVar(
		&c.showMeta,
		"meta",
		false,
		"Indicates that role binding rule metadata such "+
			"as the content hash and raft indices should be shown for each entry.",
	)

	c.flags.StringVar(
		&c.idpName,
		"idp-name",
		"",
		"Only show rules linked to the identity provider with the given name.",
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

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	rules, _, err := client.ACL().RoleBindingRuleList(c.idpName, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to retrieve the role binding rule list: %v", err))
		return 1
	}

	for _, rule := range rules {
		acl.PrintRoleBindingRule(rule, c.UI, c.showMeta)
	}

	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Lists ACL Role Binding Rules"
const help = `
Usage: consul acl rolebindingrule list [options]

  Lists all the ACL role binding rules.

    Show all:

        $ consul acl rolebindingrule list

    Show all for a specific identity provider:

        $ consul acl rolebindingrule list -idp-name="my-idp"
`
