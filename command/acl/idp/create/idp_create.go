package idpcreate

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

	idpType     string
	name        string
	description string

	k8sHost              string
	k8sCACert            string
	k8sServiceAccountJWT string

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
		&c.idpType,
		"type",
		"",
		"The new identity provider's type. This flag is required.",
	)
	c.flags.StringVar(
		&c.name,
		"name",
		"",
		"The new identity provider's name. This flag is required.",
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

	c.http = &flags.HTTPFlags{}
	flags.Merge(c.flags, c.http.ClientFlags())
	flags.Merge(c.flags, c.http.ServerFlags())
	c.help = flags.Usage(help, c.flags)
}

func (c *cmd) Run(args []string) int {
	if err := c.flags.Parse(args); err != nil {
		return 1
	}

	if c.idpType == "" {
		c.UI.Error(fmt.Sprintf("Missing required '-type' flag"))
		c.UI.Error(c.Help())
		return 1
	} else if c.name == "" {
		c.UI.Error(fmt.Sprintf("Missing required '-name' flag"))
		c.UI.Error(c.Help())
		return 1
	}

	if c.idpType != "kubernetes" {
		c.UI.Error(fmt.Sprintf("This tool can only create identity providers of type=kubernetes at this time."))
		c.UI.Error(c.Help())
		return 1
	}

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

	if c.k8sCACert[0] == '@' {
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

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	newIDP := &api.ACLIdentityProvider{
		Type:                        c.idpType,
		Name:                        c.name,
		Description:                 c.description,
		KubernetesHost:              c.k8sHost,
		KubernetesCACert:            c.k8sCACert,
		KubernetesServiceAccountJWT: c.k8sServiceAccountJWT,
	}

	idp, _, err := client.ACL().IdentityProviderCreate(newIDP, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Failed to create new identity provider: %v", err))
		return 1
	}

	aclhelpers.PrintIdentityProvider(idp, c.UI, c.showMeta)
	return 0
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Create an ACL Identity Provider"

const help = `
Usage: consul acl idp create -name NAME -type TYPE [options]

    Create a new identity provider:

        $ consul acl idp create -type "kubernetes" \
                                -name "new-idp" \
                                -description "This is an example kube idp" \
                                -kubernetes-host "https://apiserver.example.com:8443" \
                                -kubernetes-ca-file /path/to/kube.ca.crt \
                                -kubernetes-service-account-jwt "JWT_CONTENTS"
`
