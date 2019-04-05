package logout

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/consul/agent"
	"github.com/hashicorp/consul/agent/consul/kubernetesidp"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/command/acl"
	"github.com/hashicorp/consul/logger"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/consul/testrpc"
	"github.com/hashicorp/go-uuid"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestLogout_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestLogoutCommand(t *testing.T) {
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

	t.Run("no token specified", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "403 (ACL not found)")
	})

	t.Run("logout of deleted token", func(t *testing.T) {
		fakeID, err := uuid.GenerateUUID()
		require.NoError(t, err)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=" + fakeID,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "403 (ACL not found)")
	})

	plainToken, _, err := client.ACL().TokenCreate(
		&api.ACLToken{Description: "test"},
		&api.WriteOptions{Token: "root"},
	)
	require.NoError(t, err)

	t.Run("logout of ordinary token", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=" + plainToken.SecretID,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "403 (Permission denied)")
	})

	// go to the trouble of creating a login token
	// require.NoError(t, ioutil.WriteFile(idpTokenFile, []byte(acl.TestKubernetesJWT_B), 0600))

	// spin up a fake api server
	testSrv := kubernetesidp.StartTestAPIServer(t)
	defer testSrv.Stop()

	testSrv.AuthorizeJWT(acl.TestKubernetesJWT_A)
	testSrv.SetAllowedServiceAccount(
		"default",
		"demo",
		"76091af4-4b56-11e9-ac4b-708b11801cbe",
		"",
		acl.TestKubernetesJWT_B,
	)

	{
		_, _, err := client.ACL().IdentityProviderCreate(
			&api.ACLIdentityProvider{
				Name:             "k8s",
				Type:             "kubernetes",
				KubernetesHost:   testSrv.Addr(),
				KubernetesCACert: testSrv.CACert(),
				// the "A" jwt will be the one with token review privs
				KubernetesServiceAccountJWT: acl.TestKubernetesJWT_A,
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)
	}
	{
		_, _, err := client.ACL().RoleBindingRuleCreate(&api.ACLRoleBindingRule{
			IDPName:  "k8s",
			RoleName: "{{serviceaccount.name}}",
		},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)
	}

	var loginTokenSecret string
	{
		tok, _, err := client.ACL().Login(&api.ACLLoginParams{
			IDPType:  "kubernetes",
			IDPName:  "k8s",
			IDPToken: acl.TestKubernetesJWT_B,
		}, nil)
		require.NoError(t, err)

		loginTokenSecret = tok.SecretID
	}

	t.Run("logout of login token", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=" + loginTokenSecret,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 0, "err: %s", ui.ErrorWriter.String())
		require.Empty(t, ui.ErrorWriter.String())
	})
}
