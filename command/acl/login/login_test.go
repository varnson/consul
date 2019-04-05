package login

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/consul/agent"
	"github.com/hashicorp/consul/agent/consul/kubernetesidp"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/command/acl"
	"github.com/hashicorp/consul/logger"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/consul/testrpc"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestLoginCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestLoginCommand(t *testing.T) {
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

	t.Run("idp-type is required", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-idp-type' flag")
	})

	t.Run("idp-name is required", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-idp-name' flag")
	})

	tokenSinkFile := filepath.Join(testDir, "test.token")

	t.Run("token-sink-file is required", func(t *testing.T) {
		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
			"-idp-name=k8s",
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-token-sink-file' flag")
	})

	t.Run("idp-token-file is required", func(t *testing.T) {
		defer os.Remove(tokenSinkFile)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
			"-idp-name=k8s",
			"-token-sink-file", tokenSinkFile,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-idp-token-file' flag")
	})

	idpTokenFile := filepath.Join(testDir, "idp.token")

	t.Run("idp-token-file is empty", func(t *testing.T) {
		defer os.Remove(tokenSinkFile)

		require.NoError(t, ioutil.WriteFile(idpTokenFile, []byte(""), 0600))

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
			"-idp-name=k8s",
			"-token-sink-file", tokenSinkFile,
			"-idp-token-file", idpTokenFile,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "No idp token found in")
	})

	// the "B" jwt will be the one being reviewed
	require.NoError(t, ioutil.WriteFile(idpTokenFile, []byte(acl.TestKubernetesJWT_B), 0600))

	t.Run("try login with no idp configured", func(t *testing.T) {
		defer os.Remove(tokenSinkFile)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
			"-idp-name=k8s",
			"-token-sink-file", tokenSinkFile,
			"-idp-token-file", idpTokenFile,
		}

		code := cmd.Run(args)
		require.Equal(t, code, 1, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "403 (ACL not found)")
	})

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

	t.Run("try login with idp configured but no role binding rules", func(t *testing.T) {
		defer os.Remove(tokenSinkFile)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
			"-idp-name=k8s",
			"-token-sink-file", tokenSinkFile,
			"-idp-token-file", idpTokenFile,
		}

		code := cmd.Run(args)
		require.Equal(t, 1, code, "err: %s", ui.ErrorWriter.String())
		require.Contains(t, ui.ErrorWriter.String(), "403 (Permission denied)")
	})

	{
		_, _, err := client.ACL().RoleBindingRuleCreate(&api.ACLRoleBindingRule{
			IDPName:  "k8s",
			RoleName: "{{serviceaccount.name}}",
			Match: []*api.ACLRoleBindingRuleMatch{
				&api.ACLRoleBindingRuleMatch{
					Selector: []string{
						"serviceaccount.namespace=default",
					},
				},
			},
			//
		},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)
	}

	t.Run("try login with idp configured and role binding rules", func(t *testing.T) {
		defer os.Remove(tokenSinkFile)

		ui := cli.NewMockUi()
		cmd := New(ui)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-idp-type=kubernetes",
			"-idp-name=k8s",
			"-token-sink-file", tokenSinkFile,
			"-idp-token-file", idpTokenFile,
		}

		code := cmd.Run(args)
		require.Equal(t, 0, code, "err: %s", ui.ErrorWriter.String())
		require.Empty(t, ui.ErrorWriter.String())
		require.Empty(t, ui.OutputWriter.String())

		raw, err := ioutil.ReadFile(tokenSinkFile)
		require.NoError(t, err)

		token := strings.TrimSpace(string(raw))
		require.Len(t, token, 36, "must be a valid uid: %s", token)
	})
}
