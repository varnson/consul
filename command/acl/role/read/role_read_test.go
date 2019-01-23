package roleread

import (
	"fmt"
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

func TestRoleReadCommand_noTabs(t *testing.T) {
	t.Parallel()

	if strings.ContainsRune(New(cli.NewMockUi()).Help(), '\t') {
		t.Fatal("help has tabs")
	}
}

func TestRoleReadCommand(t *testing.T) {
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
	cmd := New(ui)

	client := a.Client()

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

	// read by id
	{
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-id=" + role.ID,
		}

		code := cmd.Run(args)
		require.Equal(code, 0)
		require.Empty(ui.ErrorWriter.String())

		output := ui.OutputWriter.String()
		require.Contains(output, fmt.Sprintf("test-role"))
		require.Contains(output, role.ID)
	}

	// read by name
	{
		args := []string{
			"-http-addr=" + a.HTTPAddr(),
			"-token=root",
			"-name=" + role.Name,
		}

		code := cmd.Run(args)
		require.Equal(code, 0)
		require.Empty(ui.ErrorWriter.String())

		output := ui.OutputWriter.String()
		require.Contains(output, fmt.Sprintf("test-role"))
		require.Contains(output, role.ID)
	}
}
