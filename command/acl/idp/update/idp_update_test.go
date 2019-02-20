package idpupdate

import (
	"io/ioutil"
	"os"
	"path/filepath"
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

func TestIDPUpdateCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestIDPUpdateCommand(t *testing.T) {
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

	ca := connect.TestCA(t, nil)
	ca2 := connect.TestCA(t, nil)

	t.Run("update without name", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-kubernetes-host", "https://foo.internal:8443",
			"-kubernetes-ca-cert", ca.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_A,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Cannot update an identity provider without specifying the -name parameter")
	})

	t.Run("update nonexistent idp", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=k8s",
			"-kubernetes-host", "https://foo.internal:8443",
			"-kubernetes-ca-cert", ca.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_A,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Identity Provider not found with name")
	})

	createIDP := func(t *testing.T) string {
		id, err := uuid.GenerateUUID()
		require.NoError(t, err)

		idpName := "k8s-" + id

		_, _, err = client.ACL().IdentityProviderCreate(
			&api.ACLIdentityProvider{
				Name:                        idpName,
				Type:                        "kubernetes",
				Description:                 "test idp",
				KubernetesHost:              "https://foo.internal:8443",
				KubernetesCACert:            ca.RootCert,
				KubernetesServiceAccountJWT: acl.TestKubernetesJWT_A,
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)

		return idpName
	}

	t.Run("update all fields", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-ca-cert", ca2.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo-new.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca2.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_B, idp.KubernetesServiceAccountJWT)
	})

	ca2File := filepath.Join(testDir, "ca2.crt")
	require.NoError(t, ioutil.WriteFile(ca2File, []byte(ca2.RootCert), 0600))

	t.Run("update all fields with cert file", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-ca-cert", "@" + ca2File,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo-new.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca2.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_B, idp.KubernetesServiceAccountJWT)
	})

	t.Run("update all fields but k8s host", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-ca-cert", ca2.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca2.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_B, idp.KubernetesServiceAccountJWT)
	})

	t.Run("update all fields but k8s ca cert", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo-new.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_B, idp.KubernetesServiceAccountJWT)
	})

	t.Run("update all fields but k8s jwt", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-ca-cert", ca2.RootCert,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo-new.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca2.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_A, idp.KubernetesServiceAccountJWT)
	})
}

func TestIDPUpdateCommand_noMerge(t *testing.T) {
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

	ca := connect.TestCA(t, nil)
	ca2 := connect.TestCA(t, nil)

	t.Run("update without name", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-kubernetes-host", "https://foo.internal:8443",
			"-kubernetes-ca-cert", ca.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_A,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Cannot update an identity provider without specifying the -name parameter")
	})

	t.Run("update nonexistent idp", func(t *testing.T) {
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-name=k8s",
			"-kubernetes-host", "https://foo.internal:8443",
			"-kubernetes-ca-cert", ca.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_A,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Identity Provider not found with name")
	})

	createIDP := func(t *testing.T) string {
		id, err := uuid.GenerateUUID()
		require.NoError(t, err)

		idpName := "k8s-" + id

		_, _, err = client.ACL().IdentityProviderCreate(
			&api.ACLIdentityProvider{
				Name:                        idpName,
				Type:                        "kubernetes",
				Description:                 "test idp",
				KubernetesHost:              "https://foo.internal:8443",
				KubernetesCACert:            ca.RootCert,
				KubernetesServiceAccountJWT: acl.TestKubernetesJWT_A,
			},
			&api.WriteOptions{Token: "root"},
		)
		require.NoError(t, err)

		return idpName
	}

	t.Run("update missing k8s host", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-ca-cert", ca2.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-kubernetes-host' flag")
	})

	t.Run("update missing k8s ca cert", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-kubernetes-ca-cert' flag")
	})

	t.Run("update missing k8s jwt", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-ca-cert", ca2.RootCert,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 1)
		require.Contains(t, ui.ErrorWriter.String(), "Missing required '-kubernetes-service-account-jwt' flag")
	})

	t.Run("update all fields", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-ca-cert", ca2.RootCert,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo-new.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca2.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_B, idp.KubernetesServiceAccountJWT)
	})

	ca2File := filepath.Join(testDir, "ca2.crt")
	require.NoError(t, ioutil.WriteFile(ca2File, []byte(ca2.RootCert), 0600))

	t.Run("update all fields with cert file", func(t *testing.T) {
		name := createIDP(t)

		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-no-merge",
			"-name=" + name,
			"-description", "updated description",
			"-kubernetes-host", "https://foo-new.internal:8443",
			"-kubernetes-ca-cert", "@" + ca2File,
			"-kubernetes-service-account-jwt", acl.TestKubernetesJWT_B,
		}

		ui := cli.NewMockUi()
		cmd := New(ui)

		code := cmd.Run(args)
		require.Equal(t, code, 0)
		require.Empty(t, ui.ErrorWriter.String())

		idp, _, err := client.ACL().IdentityProviderRead(
			name,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(t, err)
		require.NotNil(t, idp)
		require.Equal(t, "updated description", idp.Description)
		require.Equal(t, "https://foo-new.internal:8443", idp.KubernetesHost)
		require.Equal(t, ca2.RootCert, idp.KubernetesCACert)
		require.Equal(t, acl.TestKubernetesJWT_B, idp.KubernetesServiceAccountJWT)
	})
}
