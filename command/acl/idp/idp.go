package idp

import (
	"github.com/hashicorp/consul/command/flags"
	"github.com/mitchellh/cli"
)

func New() *cmd {
	return &cmd{}
}

type cmd struct{}

func (c *cmd) Run(args []string) int {
	return cli.RunResultHelp
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(help, nil)
}

const synopsis = "Manage Consul's ACL Identity Providers"
const help = `
Usage: consul acl idp <subcommand> [options] [args]

  This command has subcommands for managing Consul's ACL Identity Providers.
  Here are some simple examples, and more detailed examples are available
  in the subcommands or the documentation.

  Create a new ACL Identity Provider:

      $ consul acl idp create -type kubernetes \
                              -name "kube-1" \
                              -description "This is an example kube idp"

  List all identity providers:

      $ consul acl idp list

  Update a identity provider:

    $ consul acl idp update -name "kube-1" \
                            -kubernetes-host="https://apiserver.example.com:8443"

  Read a identity provider:

    $ consul acl idp read -name kube-1

  Delete a identity provider:

    $ consul acl idp delete -name "kube-1"

  For more examples, ask for subcommand help or view the documentation.
`
