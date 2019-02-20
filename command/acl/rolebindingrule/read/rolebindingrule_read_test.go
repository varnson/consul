package rolebindingruleread

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
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestRoleBindingRuleReadCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestRoleBindingRuleReadCommand(t *testing.T) {
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

	createRule := func(t *testing.T) string {
		rule, _, err := client.ACL().RoleBindingRuleCreate(
			&api.ACLRoleBindingRule{
				IDPName:     "k8s",
				Description: "test rule",
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

	t.Run("id required", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Must specify the -id parameter")
	})

	t.Run("read by id not found", func(t *testing.T) {
		fakeID, err := uuid.GenerateUUID()
		require.NoError(t, err)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-id=" + fakeID,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Role binding rule not found with ID")
	})

	t.Run("read by id", func(t *testing.T) {
		id := createRule(t)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-id=" + id,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		output := ui.OutputWriter.String()
		require.Contains(t, output, fmt.Sprintf("test rule"))
		require.Contains(t, output, id)
	})

	t.Run("read by id prefix", func(t *testing.T) {
		id := createRule(t)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-id=" + id[0:5],
		}

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		output := ui.OutputWriter.String()
		require.Contains(t, output, fmt.Sprintf("test rule"))
		require.Contains(t, output, id)
	})
}
