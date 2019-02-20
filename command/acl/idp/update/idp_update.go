package idpupdate

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/consul/api"
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

	name string

	description string

	k8sHost              string
	k8sCACert            string
	k8sServiceAccountJWT string

	noMerge  bool
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
		"The identity provider name.",
	)

	c.flags.StringVar(
		&c.description,
		"description",
		"",
		"A description of the identity provider.",
	)

	c.flags.StringVar(
		&c.k8sHost,
		"kubernetes-host",
		"",
		"Address of the Kubernetes API server. This flag is required for type=kubernetes.",
	)
	c.flags.StringVar(
		&c.k8sCACert,
		"kubernetes-ca-cert",
		"",
		"PEM encoded CA cert for use by the TLS client used to talk with the "+
			"Kubernetes API. May be prefixed with '@' to indicate that the "+
			"value is a file path to load the cert from. "+
			"This flag is required for type=kubernetes.",
	)
	c.flags.StringVar(
		&c.k8sServiceAccountJWT,
		"kubernetes-service-account-jwt",
		"",
		"A kubernetes service account JWT used to access the TokenReview API to "+
			"validate other JWTs during login. "+
			"This flag is required for type=kubernetes.",
	)

	c.flags.BoolVar(&c.noMerge, "no-merge", false, "Do not merge the current identity provider "+
		"information with what is provided to the command. Instead overwrite all fields "+
		"with the exception of the name which is immutable.")

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
		c.UI.Error(fmt.Sprintf("Cannot update an identity provider without specifying the -name parameter"))
		return 1
	}

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	// Regardless of merge, we need to fetch the prior immutable fields first.
	currentIDP, _, err := client.ACL().IdentityProviderRead(c.name, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error when retrieving current identity provider: %v", err))
		return 1
	} else if currentIDP == nil {
		c.UI.Error(fmt.Sprintf("Identity Provider not found with name %q", c.name))
		return 1
	}

	if currentIDP.Type != "kubernetes" {
		c.UI.Error(fmt.Sprintf("This tool can only update identity providers of type=kubernetes at this time."))
		c.UI.Error(c.Help())
		return 1
	}

	if c.k8sCACert != "" && c.k8sCACert[0] == '@' {
		data, err := ioutil.ReadFile(c.k8sCACert[1:])
		if err != nil {
			c.UI.Error(fmt.Sprintf("Failed to read %s: %s", c.k8sCACert, err))
		}
		c.k8sCACert = string(data)

		if c.k8sCACert == "" {
			c.UI.Error(fmt.Sprintf("Kubernetes CA Cert File is empty"))
			return 1
		}
	}

	var idp *api.ACLIdentityProvider
	if c.noMerge {
		if c.k8sHost == "" {
			c.UI.Error(fmt.Sprintf("Missing required '-kubernetes-host' flag"))
			return 1
		} else if c.k8sCACert == "" {
			c.UI.Error(fmt.Sprintf("Missing required '-kubernetes-ca-cert' flag"))
			return 1
		} else if c.k8sServiceAccountJWT == "" {
			c.UI.Error(fmt.Sprintf("Missing required '-kubernetes-service-account-jwt' flag"))
			return 1
		}

		idp = &api.ACLIdentityProvider{
			Name:                        currentIDP.Name,
			Type:                        currentIDP.Type,
			Description:                 c.description,
			KubernetesHost:              c.k8sHost,
			KubernetesCACert:            c.k8sCACert,
			KubernetesServiceAccountJWT: c.k8sServiceAccountJWT,
		}
	} else {
		idpCopy := *currentIDP
		idp = &idpCopy

		if c.description != "" {
			idp.Description = c.description
		}
		if c.k8sHost != "" {
			idp.KubernetesHost = c.k8sHost
		}
		if c.k8sCACert != "" {
			idp.KubernetesCACert = c.k8sCACert
		}
		if c.k8sServiceAccountJWT != "" {
			idp.KubernetesServiceAccountJWT = c.k8sServiceAccountJWT
		}
	}

	idp, _, err = client.ACL().IdentityProviderUpdate(idp, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error updating identity provider %q: %v", c.name, err))
		return 1
	}

	c.UI.Info(fmt.Sprintf("Identity Provider updated successfully"))
	aclhelpers.PrintIdentityProvider(idp, c.UI, c.showMeta)
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Update an ACL Identity Provider"
const help = `
Usage: consul acl idp update -name NAME [options]

  Updates an identity provider. By default it will merge the identity provider
  information with its current state so that you do not have to provide all
  parameters. This behavior can be disabled by passing -no-merge.

    Update all editable fields of the identity provider:

        $ consul acl idp update -name "my-idp" \
                                -description "new description" \
                                -kubernetes-host "https://new-apiserver.example.com:8443" \
                                -kubernetes-ca-file /path/to/new-kube.ca.crt \
                                -kubernetes-service-account-jwt "NEW_JWT_CONTENTS"
`
