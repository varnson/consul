package rolebindingruleread

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

	ruleID string

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
		&c.ruleID,
		"id",
		"",
		"The ID of the role binding rule to read. "+
			"It may be specified as a unique ID prefix but will error if the prefix "+
			"matches multiple role binding rule IDs",
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

	if c.ruleID == "" {
		c.UI.Error(fmt.Sprintf("Must specify the -id parameter."))
		return 1
	}

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	ruleID, err := acl.GetRoleBindingRuleIDFromPartial(client, c.ruleID)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error determining role binding rule ID: %v", err))
		return 1
	}

	rule, _, err := client.ACL().RoleBindingRuleRead(ruleID, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading role binding rule %q: %v", ruleID, err))
		return 1
	} else if rule == nil {
		c.UI.Error(fmt.Sprintf("Role binding rule not found with ID %q", ruleID))
		return 1
	}

	acl.PrintRoleBindingRule(rule, c.UI, c.showMeta)
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Read an ACL Role Binding Rule"
const help = `
Usage: consul acl rolebindingrule read -id ID [options]

  This command will retrieve and print out the details of a single
  role binding rule.

    Read:

     $ consul acl rolebindingrule read -id fdabbcb5-9de5-4b1a-961f-77214ae88cba
`
