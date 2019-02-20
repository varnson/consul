package rolebindingrulecreate

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/consul/agent"
	"github.com/hashicorp/consul/agent/connect"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/command/acl"
	"github.com/hashicorp/consul/logger"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/consul/testrpc"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestRoleBindingRuleCreateCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestRoleBindingRuleCreateCommand(t *testing.T) {
	t.Parallel()

	testDir := testutil.TempDir(t, "acl")
	defer os.RemoveAll(testDir)

	a := agent.NewTestAgent(t, t.Name(), `
	primary_datacenter = "dc1"
	acl {
		enabled = true
		tokens {
			master = "root"
		}
	}`)

	a.Agent.LogWriter = logger.NewLogWriter(512)

	defer a.Shutdown()
	testrpc.WaitForLeader(t, a.RPC, "dc1")

	client := a.Client()

	// create an idp in advance
	{
		ca := connect.TestCA(t, nil)
		_, _, err := client.ACL().IdentityProviderCreate(
			&api.ACLIdentityProvider{
				Name:                        "k8s",
				Type:                        "kubernetes",
				KubernetesHost:              "https://foo.internal:8443",
				KubernetesCACert:            ca.RootCert,
				KubernetesServiceAccountJWT: acl.TestKubernetesJWT_A,
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)
	}

	t.Run("idp name required", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-idp-name' flag")
	})

	t.Run("role name required", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-name=k8s",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-role-name' flag")
	})

	t.Run("must use roughly valid match selectors", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-name=k8s",
			"-role-name=demo",
			"-match-selector", " , ",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Invalid match selector")
	})

	t.Run("create it with no match selectors", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-name=k8s",
			"-role-name=demo",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())
	})

	t.Run("create it with 2 match selectors", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-name=k8s",
			"-role-name=demo",
			"-match-selector", "serviceaccount.name=demo",
			"-match-selector", "serviceaccount.namespace=default,serviceaccount.name=vault",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())
		// TODO: verify both selectors made it
	})
}
