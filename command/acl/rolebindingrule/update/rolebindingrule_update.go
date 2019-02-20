package rolebindingruleupdate

import (
	"flag"
	"fmt"

	"github.com/hashicorp/consul/api"
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

	description    string
	matchSelectors []string
	roleName       string
	mustExist      bool

	noMerge  bool
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
		"The ID of the role binding rule to update. "+
			"It may be specified as a unique ID prefix but will error if the prefix "+
			"matches multiple role binding rule IDs",
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

	c.flags.BoolVar(
		&c.noMerge,
		"no-merge",
		false,
		"Do not merge the current role binding rule "+
			"information with what is provided to the command. Instead overwrite all fields "+
			"with the exception of the role binding rule ID which is immutable.",
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
		c.UI.Error(fmt.Sprintf("Cannot update a role binding rule without specifying the -id parameter"))
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

	found, err := acl.ParseRoleBindingRuleMatchSelectors(c.matchSelectors)
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Read the current role binding rule in both cases so we can fail better if not found.
	currentRule, _, err := client.ACL().RoleBindingRuleRead(ruleID, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error when retrieving current role binding rule: %v", err))
		return 1
	} else if currentRule == nil {
		c.UI.Error(fmt.Sprintf("Role binding rule not found with ID %q", ruleID))
		return 1
	}

	var rule *api.ACLRoleBindingRule
	if c.noMerge {
		if c.roleName == "" {
			c.UI.Error(fmt.Sprintf("Missing required '-role-name' flag"))
			c.UI.Error(c.Help())
			return 1
		}

		rule = &api.ACLRoleBindingRule{
			ID:          ruleID,
			IDPName:     currentRule.IDPName, // immutable
			Description: c.description,
			RoleName:    c.roleName,
			MustExist:   c.mustExist,
			Match:       found,
		}

	} else {
		rule = currentRule

		if c.description != "" {
			rule.Description = c.description
		}
		if c.roleName != "" {
			rule.RoleName = c.roleName
		}
		if isFlagSet(c.flags, "must-exist") {
			rule.MustExist = c.mustExist
		}

		if len(found) > 0 {
			rule.Match = append(rule.Match, found...)
		}
	}

	rule, _, err = client.ACL().RoleBindingRuleUpdate(rule, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error updating role binding rule %q: %v", ruleID, err))
		return 1
	}

	c.UI.Info(fmt.Sprintf("Role binding rule updated successfully"))
	acl.PrintRoleBindingRule(rule, c.UI, c.showMeta)
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

func isFlagSet(flags *flag.FlagSet, name string) bool {
	found := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

const synopsis = "Update an ACL Role Binding Rule"
const help = `
Usage: consul acl rolebindingrule update -id ID [options]

  Updates a role binding rule. By default it will merge the role binding rule
  information with its current state so that you do not have to provide all
  parameters. This behavior can be disabled by passing -no-merge.

    Update all editable fields of the role binding rule:

     $ consul acl rolebindingrule update \
            -id=43cb72df-9c6f-4315-ac8a-01a9d98155ef \
            -description="new description" \
            -role-name="k8s-{{serviceaccount.name}}" \
            -must-exist \
            -match-selector='serviceaccount.namespace=default,serviceaccount.name=web' \
            -match-selector='serviceaccount.namespace=default,serviceaccount.name=db'
`
