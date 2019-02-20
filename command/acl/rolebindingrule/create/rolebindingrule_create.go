package rolebindingrulecreate

import (
	"flag"
	"fmt"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/command/acl"
	aclhelpers "github.com/hashicorp/consul/command/acl"
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

	idpName        string
	description    string
	matchSelectors []string
	roleName       string
	mustExist      bool

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
		"The identity provider's name for which this role binding rule applies. "+
			"This flag is required.",
	)
	c.flags.StringVar(
		&c.description,
		"description",
		"",
		"A description of the role binding rule.",
	)
	c.flags.Var(
		(*flags.AppendSliceValue)(&c.matchSelectors),
		"match-selector",
		"Comma separated list of match selectors in the format KEY1=VAL1,KEY2=VAL2. "+
			"May be specified multiple times.",
	)
	c.flags.StringVar(
		&c.roleName,
		"role-name",
		"",
		"Name of role to bind on match. Can use {{var}} interpolation. "+
			"This flag is required.",
	)
	c.flags.BoolVar(
		&c.mustExist,
		"must-exist",
		false,
		"If true, a role with a name matching the one specified with -role-name "+
			"must exist at login time for the login to succeed.",
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

	if c.idpName == "" {
		c.UI.Error(fmt.Sprintf("Missing required '-idp-name' flag"))
		c.UI.Error(c.Help())
		return 1
	} else if c.roleName == "" {
		c.UI.Error(fmt.Sprintf("Missing required '-role-name' flag"))
		c.UI.Error(c.Help())
		return 1
	}

	found, err := acl.ParseRoleBindingRuleMatchSelectors(c.matchSelectors)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	newRule := &api.ACLRoleBindingRule{
		Description: c.description,
		IDPName:     c.idpName,
		RoleName:    c.roleName,
		MustExist:   c.mustExist,
		Match:       found,
	}

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	rule, _, err := client.ACL().RoleBindingRuleCreate(newRule, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to create new role binding rule: %v", err))
		return 1
	}

	aclhelpers.PrintRoleBindingRule(rule, c.UI, c.showMeta)
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Create an ACL Role Binding Rule"

const help = `
Usage: consul acl rolebindingrule create [options]

  Create a new role binding rule:

     $ consul acl rolebindingrule create \
            -idp-name=minikube \
            -role-name="k8s-{{serviceaccount.name}}" \
            -match-selector='serviceaccount.namespace=default,serviceaccount.name=web' \
            -match-selector='serviceaccount.namespace=default,serviceaccount.name=db'
`
