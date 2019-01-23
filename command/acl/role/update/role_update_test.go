package roleupdate

import (
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/consul/agent"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/logger"
	"github.com/hashicorp/consul/testrpc"
	"github.com/hashicorp/consul/testutil"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestRoleUpdateCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestRoleUpdateCommand(t *testing.T) {
	t.Parallel()
	require := require.New(t)

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

	ui := cli.NewMockUi()

	client := a.Client()

	// Create 2 policies
	policy1, _, err := client.ACL().PolicyCreate(
		&api.ACLPolicy{Name: "test-policy1"},
		&api.WriteOptions{Token: "root"},
	)
	require.NoError(err)
	policy2, _, err := client.ACL().PolicyCreate(
		&api.ACLPolicy{Name: "test-policy2"},
		&api.WriteOptions{Token: "root"},
	)
	require.NoError(err)

	// create a role
	role, _, err := client.ACL().RoleCreate(
		&api.ACLRole{
			Name: "test-role",
			ServiceIdentities: []*api.ACLServiceIdentity{
				&api.ACLServiceIdentity{
					ServiceName: "fake",
				},
			},
		},
		&api.WriteOptions{Token: "root"},
	)
	require.NoError(err)

	// update with policy by name
	{
		cmd := New(ui)
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-id=" + role.ID,
			"-token=root",
			"-policy-name=" + policy1.Name,
			"-description=test role edited",
		}

		code := cmd.Run(args)
		require.Equal(code, 0)
		require.Empty(ui.ErrorWriter.String())

		role, _, err := client.ACL().RoleRead(
			role.ID,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(err)
		require.NotNil(role)
		// TODO verify policy count == 1 && svcid count == 1
	}

	// update with policy by id; also update with no description shouldn't
	// delete the current description
	{
		cmd := New(ui)
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-id=" + role.ID,
			"-token=root",
			"-policy-id=" + policy2.ID,
		}

		code := cmd.Run(args)
		require.Equal(code, 0)
		require.Empty(ui.ErrorWriter.String())

		role, _, err := client.ACL().RoleRead(
			role.ID,
			&api.QueryOptions{Token: "root"},
		)
		require.NoError(err)
		require.NotNil(role)
		require.Equal("test role edited", role.Description)
		// TODO verify policy count == 2 && svcid count == 1
	}
}
