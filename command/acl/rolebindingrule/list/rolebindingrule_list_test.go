package rolebindingrulelist

import (
	"fmt"
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

func TestRoleBindingRuleListCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestRoleBindingRuleListCommand(t *testing.T) {
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

	// Create a couple roles to list
	client := a.Client()

	{
		ca := connect.TestCA(t, nil)
		ca2 := connect.TestCA(t, nil)
		_, _, err := client.ACL().IdentityProviderCreate(
			&api.ACLIdentityProvider{
				Name:                        "k8s-1",
				Type:                        "kubernetes",
				KubernetesHost:              "https://foo.internal:8443",
				KubernetesCACert:            ca.RootCert,
				KubernetesServiceAccountJWT: acl.TestKubernetesJWT_A,
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)

		_, _, err = client.ACL().IdentityProviderCreate(
			&api.ACLIdentityProvider{
				Name:                        "k8s-2",
				Type:                        "kubernetes",
				KubernetesHost:              "https://foo.internal:8443",
				KubernetesCACert:            ca2.RootCert,
				KubernetesServiceAccountJWT: acl.TestKubernetesJWT_A,
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)
	}

	createRule := func(t *testing.T, idpName, description string) string {
		rule, _, err := client.ACL().RoleBindingRuleCreate(
			&api.ACLRoleBindingRule{
				IDPName:     idpName,
				Description: description,
				RoleName:    "k8s-{{serviceaccount.name}}",
				MustExist:   false,
				Match: []*api.ACLRoleBindingRuleMatch{
					&api.ACLRoleBindingRuleMatch{
						Selector: []string{
							"serviceaccount.namespace=default",
						},
					},
				},
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)
		return rule.ID
	}

	var ruleIDs []string
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("test-rule-%d", i)

		var idpName string
		if i%2 == 0 {
			idpName = "k8s-1"
		} else {
			idpName = "k8s-2"
		}

		id := createRule(t, idpName, name)

		ruleIDs = append(ruleIDs, id)
	}

	t.Run("normal", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())
		output := ui.OutputWriter.String()

		for i, v := range ruleIDs {
			require.Contains(t, output, fmt.Sprintf("test-rule-%d", i))
			require.Contains(t, output, v)
		}
	})

	t.Run("filter by idp 1", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-name=k8s-1",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())
		output := ui.OutputWriter.String()

		for i, v := range ruleIDs {
			if i%2 == 0 {
				require.Contains(t, output, fmt.Sprintf("test-rule-%d", i))
				require.Contains(t, output, v)
			}
		}
	})

	t.Run("filter by idp 2", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-name=k8s-2",
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())
		output := ui.OutputWriter.String()

		for i, v := range ruleIDs {
			if i%2 == 1 {
				require.Contains(t, output, fmt.Sprintf("test-rule-%d", i))
				require.Contains(t, output, v)
			}
		}
	})
}
