package acl

import (
	"fmt"
	"strings"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/api"
	"github.com/mitchellh/cli"
)

func PrintToken(token *api.ACLToken, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("AccessorID:       %s", token.AccessorID))
	ui.Info(fmt.Sprintf("SecretID:         %s", token.SecretID))
	ui.Info(fmt.Sprintf("Description:      %s", token.Description))
	ui.Info(fmt.Sprintf("Local:            %t", token.Local))
	ui.Info(fmt.Sprintf("Create Time:      %v", token.CreateTime))
	if !token.ExpirationTime.IsZero() {
		ui.Info(fmt.Sprintf("Expiration Time:  %v", token.ExpirationTime))
	}
	if showMeta {
		ui.Info(fmt.Sprintf("Hash:             %x", token.Hash))
		ui.Info(fmt.Sprintf("Create Index:     %d", token.CreateIndex))
		ui.Info(fmt.Sprintf("Modify Index:     %d", token.ModifyIndex))
	}
	ui.Info(fmt.Sprintf("Policies:"))
	for _, policy := range token.Policies {
		ui.Info(fmt.Sprintf("   %s - %s", policy.ID, policy.Name))
	}
	ui.Info(fmt.Sprintf("Roles:"))
	for _, role := range token.Roles {
		if role.BoundName == "" {
			ui.Info(fmt.Sprintf("   %s - %s", role.ID, role.Name))
		} else {
			ui.Info(fmt.Sprintf("   %s", role.BoundName))
		}
	}
	ui.Info(fmt.Sprintf("Service Identities:"))
	for _, svcid := range token.ServiceIdentities {
		if len(svcid.Datacenters) > 0 {
			ui.Info(fmt.Sprintf("   %s (Datacenters: %s)", svcid.ServiceName, strings.Join(svcid.Datacenters, ", ")))
		} else {
			ui.Info(fmt.Sprintf("   %s (Datacenters: all)", svcid.ServiceName))
		}
	}
	if token.Rules != "" {
		ui.Info(fmt.Sprintf("Rules:"))
		ui.Info(token.Rules)
	}
}

func PrintTokenListEntry(token *api.ACLTokenListEntry, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("AccessorID:       %s", token.AccessorID))
	ui.Info(fmt.Sprintf("Description:      %s", token.Description))
	ui.Info(fmt.Sprintf("Local:            %t", token.Local))
	ui.Info(fmt.Sprintf("Create Time:      %v", token.CreateTime))
	if !token.ExpirationTime.IsZero() {
		ui.Info(fmt.Sprintf("Expiration Time:  %v", token.ExpirationTime))
	}
	ui.Info(fmt.Sprintf("Legacy:           %t", token.Legacy))
	if showMeta {
		ui.Info(fmt.Sprintf("Hash:             %x", token.Hash))
		ui.Info(fmt.Sprintf("Create Index:     %d", token.CreateIndex))
		ui.Info(fmt.Sprintf("Modify Index:     %d", token.ModifyIndex))
	}
	ui.Info(fmt.Sprintf("Policies:"))
	for _, policy := range token.Policies {
		ui.Info(fmt.Sprintf("   %s - %s", policy.ID, policy.Name))
	}
	ui.Info(fmt.Sprintf("Roles:"))
	for _, role := range token.Roles {
		if role.BoundName == "" {
			ui.Info(fmt.Sprintf("   %s - %s", role.ID, role.Name))
		} else {
			ui.Info(fmt.Sprintf("   %s", role.BoundName))
		}
	}
	ui.Info(fmt.Sprintf("Service Identities:"))
	for _, svcid := range token.ServiceIdentities {
		if len(svcid.Datacenters) > 0 {
			ui.Info(fmt.Sprintf("   %s (Datacenters: %s)", svcid.ServiceName, strings.Join(svcid.Datacenters, ", ")))
		} else {
			ui.Info(fmt.Sprintf("   %s (Datacenters: all)", svcid.ServiceName))
		}
	}
}

func PrintPolicy(policy *api.ACLPolicy, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("ID:           %s", policy.ID))
	ui.Info(fmt.Sprintf("Name:         %s", policy.Name))
	ui.Info(fmt.Sprintf("Description:  %s", policy.Description))
	ui.Info(fmt.Sprintf("Datacenters:  %s", strings.Join(policy.Datacenters, ", ")))
	if showMeta {
		ui.Info(fmt.Sprintf("Hash:         %x", policy.Hash))
		ui.Info(fmt.Sprintf("Create Index: %d", policy.CreateIndex))
		ui.Info(fmt.Sprintf("Modify Index: %d", policy.ModifyIndex))
	}
	ui.Info(fmt.Sprintf("Rules:"))
	ui.Info(policy.Rules)
}

func PrintPolicyListEntry(policy *api.ACLPolicyListEntry, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("%s:", policy.Name))
	ui.Info(fmt.Sprintf("   ID:           %s", policy.ID))
	ui.Info(fmt.Sprintf("   Description:  %s", policy.Description))
	ui.Info(fmt.Sprintf("   Datacenters:  %s", strings.Join(policy.Datacenters, ", ")))
	if showMeta {
		ui.Info(fmt.Sprintf("   Hash:         %x", policy.Hash))
		ui.Info(fmt.Sprintf("   Create Index: %d", policy.CreateIndex))
		ui.Info(fmt.Sprintf("   Modify Index: %d", policy.ModifyIndex))
	}
}

func PrintRole(role *api.ACLRole, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("ID:           %s", role.ID))
	ui.Info(fmt.Sprintf("Name:         %s", role.Name))
	ui.Info(fmt.Sprintf("Description:  %s", role.Description))
	if showMeta {
		ui.Info(fmt.Sprintf("Hash:         %x", role.Hash))
		ui.Info(fmt.Sprintf("Create Index: %d", role.CreateIndex))
		ui.Info(fmt.Sprintf("Modify Index: %d", role.ModifyIndex))
	}
	ui.Info(fmt.Sprintf("Policies:"))
	for _, policy := range role.Policies {
		ui.Info(fmt.Sprintf("   %s - %s", policy.ID, policy.Name))
	}
	ui.Info(fmt.Sprintf("Service Identities:"))
	for _, svcid := range role.ServiceIdentities {
		if len(svcid.Datacenters) > 0 {
			ui.Info(fmt.Sprintf("   %s (Datacenters: %s)", svcid.ServiceName, strings.Join(svcid.Datacenters, ", ")))
		} else {
			ui.Info(fmt.Sprintf("   %s (Datacenters: all)", svcid.ServiceName))
		}
	}
}

func PrintRoleListEntry(role *api.ACLRoleListEntry, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("%s:", role.Name))
	ui.Info(fmt.Sprintf("   ID:           %s", role.ID))
	ui.Info(fmt.Sprintf("   Description:  %s", role.Description))
	if showMeta {
		ui.Info(fmt.Sprintf("   Hash:         %x", role.Hash))
		ui.Info(fmt.Sprintf("   Create Index: %d", role.CreateIndex))
		ui.Info(fmt.Sprintf("   Modify Index: %d", role.ModifyIndex))
	}
	ui.Info(fmt.Sprintf("Policies:"))
	for _, policy := range role.Policies {
		ui.Info(fmt.Sprintf("   %s - %s", policy.ID, policy.Name))
	}
	ui.Info(fmt.Sprintf("Service Identities:"))
	for _, svcid := range role.ServiceIdentities {
		if len(svcid.Datacenters) > 0 {
			ui.Info(fmt.Sprintf("   %s (Datacenters: %s)", svcid.ServiceName, strings.Join(svcid.Datacenters, ", ")))
		} else {
			ui.Info(fmt.Sprintf("   %s (Datacenters: all)", svcid.ServiceName))
		}
	}
}

func PrintIdentityProvider(idp *api.ACLIdentityProvider, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("Name:         %s", idp.Name))
	ui.Info(fmt.Sprintf("Type:         %s", idp.Type))
	ui.Info(fmt.Sprintf("Description:  %s", idp.Description))
	if showMeta {
		ui.Info(fmt.Sprintf("Create Index: %d", idp.CreateIndex))
		ui.Info(fmt.Sprintf("Modify Index: %d", idp.ModifyIndex))
	}
	if idp.Type == "kubernetes" {
		ui.Info(fmt.Sprintf("Kubernetes:"))
		ui.Info(fmt.Sprintf("  Host: %s", idp.KubernetesHost))
		ui.Info(fmt.Sprintf("  CA Cert:"))
		if idp.KubernetesCACert != "" {
			ui.Info(fmt.Sprintf("    %s", idp.KubernetesCACert))
		}
		ui.Info(fmt.Sprintf("  Service Account JWT:"))
		if idp.KubernetesServiceAccountJWT != "" {
			ui.Info(fmt.Sprintf("    %s", idp.KubernetesServiceAccountJWT))
		}
	}
}

func PrintIdentityProviderListEntry(idp *api.ACLIdentityProviderListEntry, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("%s:", idp.Name))
	ui.Info(fmt.Sprintf("   Type:         %s", idp.Type))
	ui.Info(fmt.Sprintf("   Description:  %s", idp.Description))
	if showMeta {
		ui.Info(fmt.Sprintf("   Create Index: %d", idp.CreateIndex))
		ui.Info(fmt.Sprintf("   Modify Index: %d", idp.ModifyIndex))
	}
	if idp.Type == "kubernetes" {
		ui.Info(fmt.Sprintf("Kubernetes:"))
		ui.Info(fmt.Sprintf("  Host: %s", idp.KubernetesHost))
	}
}

func PrintRoleBindingRule(rule *api.ACLRoleBindingRule, ui cli.Ui, showMeta bool) {
	ui.Info(fmt.Sprintf("ID:           %s", rule.ID))
	ui.Info(fmt.Sprintf("IDPName:      %s", rule.IDPName))
	ui.Info(fmt.Sprintf("Description:  %s", rule.Description))
	ui.Info(fmt.Sprintf("RoleName:     %s", rule.RoleName))
	ui.Info(fmt.Sprintf("MustExist:    %v", rule.MustExist))
	if showMeta {
		ui.Info(fmt.Sprintf("Create Index: %d", rule.CreateIndex))
		ui.Info(fmt.Sprintf("Modify Index: %d", rule.ModifyIndex))
	}
	ui.Info(fmt.Sprintf("Match:"))
	for i, match := range rule.Match {
		ui.Info(fmt.Sprintf("  %d:", i))
		for _, sel := range match.Selector {
			ui.Info(fmt.Sprintf("     %s", sel))
		}
	}
}

func GetTokenIDFromPartial(client *api.Client, partialID string) (string, error) {
	if partialID == "anonymous" {
		return structs.ACLTokenAnonymousID, nil
	}

	// the full UUID string was given
	if len(partialID) == 36 {
		return partialID, nil
	}

	tokens, _, err := client.ACL().TokenList(nil)
	if err != nil {
		return "", err
	}

	tokenID := ""
	for _, token := range tokens {
		if strings.HasPrefix(token.AccessorID, partialID) {
			if tokenID != "" {
				return "", fmt.Errorf("Partial token ID is not unique")
			}
			tokenID = token.AccessorID
		}
	}

	if tokenID == "" {
		return "", fmt.Errorf("No such token ID with prefix: %s", partialID)
	}

	return tokenID, nil
}

func GetPolicyIDFromPartial(client *api.Client, partialID string) (string, error) {
	if partialID == "global-management" {
		return structs.ACLPolicyGlobalManagementID, nil
	}
	// The full UUID string was given
	if len(partialID) == 36 {
		return partialID, nil
	}

	policies, _, err := client.ACL().PolicyList(nil)
	if err != nil {
		return "", err
	}

	policyID := ""
	for _, policy := range policies {
		if strings.HasPrefix(policy.ID, partialID) {
			if policyID != "" {
				return "", fmt.Errorf("Partial policy ID is not unique")
			}
			policyID = policy.ID
		}
	}

	if policyID == "" {
		return "", fmt.Errorf("No such policy ID with prefix: %s", partialID)
	}

	return policyID, nil
}

func GetPolicyIDByName(client *api.Client, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("No name specified")
	}

	policies, _, err := client.ACL().PolicyList(nil)
	if err != nil {
		return "", err
	}

	for _, policy := range policies {
		if policy.Name == name {
			return policy.ID, nil
		}
	}

	return "", fmt.Errorf("No such policy with name %s", name)
}

func GetRulesFromLegacyToken(client *api.Client, tokenID string, isSecret bool) (string, error) {
	tokenID, err := GetTokenIDFromPartial(client, tokenID)
	if err != nil {
		return "", err
	}

	var token *api.ACLToken
	if isSecret {
		qopts := api.QueryOptions{
			Token: tokenID,
		}
		token, _, err = client.ACL().TokenReadSelf(&qopts)
	} else {
		token, _, err = client.ACL().TokenRead(tokenID, nil)
	}

	if err != nil {
		return "", fmt.Errorf("Error reading token: %v", err)
	}

	if token == nil {
		return "", fmt.Errorf("Token not found for ID")
	}

	if token.Rules == "" {
		return "", fmt.Errorf("Token is not a legacy token with rules")
	}

	return token.Rules, nil
}

func GetRoleIDFromPartial(client *api.Client, partialID string) (string, error) {
	// the full UUID string was given
	if len(partialID) == 36 {
		return partialID, nil
	}

	roles, _, err := client.ACL().RoleList(nil)
	if err != nil {
		return "", err
	}

	roleID := ""
	for _, role := range roles {
		if strings.HasPrefix(role.ID, partialID) {
			if roleID != "" {
				return "", fmt.Errorf("Partial role ID is not unique")
			}
			roleID = role.ID
		}
	}

	if roleID == "" {
		return "", fmt.Errorf("No such role ID with prefix: %s", partialID)
	}

	return roleID, nil
}

func GetRoleIDByName(client *api.Client, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("No name specified")
	}

	roles, _, err := client.ACL().RoleList(nil)
	if err != nil {
		return "", err
	}

	for _, role := range roles {
		if role.Name == name {
			return role.ID, nil
		}
	}

	return "", fmt.Errorf("No such role with name %s", name)
}

func GetRoleBindingRuleIDFromPartial(client *api.Client, partialID string) (string, error) {
	// the full UUID string was given
	if len(partialID) == 36 {
		return partialID, nil
	}

	rules, _, err := client.ACL().RoleBindingRuleList("", nil)
	if err != nil {
		return "", err
	}

	ruleID := ""
	for _, rule := range rules {
		if strings.HasPrefix(rule.ID, partialID) {
			if ruleID != "" {
				return "", fmt.Errorf("Partial rule ID is not unique")
			}
			ruleID = rule.ID
		}
	}

	if ruleID == "" {
		return "", fmt.Errorf("No such rule ID with prefix: %s", partialID)
	}

	return ruleID, nil
}

func ExtractServiceIdentities(serviceIdents []string) ([]*api.ACLServiceIdentity, error) {
	var out []*api.ACLServiceIdentity
	for _, svcidRaw := range serviceIdents {
		parts := strings.Split(svcidRaw, ":")
		switch len(parts) {
		case 2:
			out = append(out, &api.ACLServiceIdentity{
				ServiceName: parts[0],
				Datacenters: strings.Split(parts[1], ","),
			})
		case 1:
			out = append(out, &api.ACLServiceIdentity{
				ServiceName: parts[0],
			})
		default:
			return nil, fmt.Errorf("Malformed -service-identity argument: %q", svcidRaw)
		}
	}
	return out, nil
}

func ParseRoleBindingRuleMatchSelectors(matchSelectors []string) ([]*api.ACLRoleBindingRuleMatch, error) {
	var found []*api.ACLRoleBindingRuleMatch

	for _, rawMatch := range matchSelectors {
		rawSelectors := strings.Split(rawMatch, ",")
		if len(rawSelectors) == 0 {
			return nil, fmt.Errorf("Invalid match selector: %s", rawMatch)
		}

		var m api.ACLRoleBindingRuleMatch
		for _, rawSelector := range rawSelectors {
			selector := strings.TrimSpace(rawSelector)
			if selector == "" {
				return nil, fmt.Errorf("Invalid match selector: %s", rawMatch)
			}
			m.Selector = append(m.Selector, selector)
		}

		found = append(found, &m)
	}

	return found, nil
}

// TestKubernetesJWT_A is a valid service account jwt extracted from a minikube setup.
const TestKubernetesJWT_A = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlbW8tdG9rZW4ta21iOW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVtbyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijc2MDkxYWY0LTRiNTYtMTFlOS1hYzRiLTcwOGIxMTgwMWNiZSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlbW8ifQ.ZiAHjijBAOsKdum0Aix6lgtkLkGo9_Tu87dWQ5Zfwnn3r2FejEWDAnftTft1MqqnMzivZ9Wyyki5ZjQRmTAtnMPJuHC-iivqY4Wh4S6QWCJ1SivBv5tMZR79t5t8mE7R1-OHwst46spru1pps9wt9jsA04d3LpV0eeKYgdPTVaQKklxTm397kIMUugA6yINIBQ3Rh8eQqBgNwEmL4iqyYubzHLVkGkoP9MJikFI05vfRiHtYr-piXz6JFDzXMQj9rW6xtMmrBSn79ChbyvC5nz-Nj2rJPnHsb_0rDUbmXY5PpnMhBpdSH-CbZ4j8jsiib6DtaGJhVZeEQ1GjsFAZwQ"

// TestKubernetesJWT_B is a valid service account jwt extracted from a minikube setup.
const TestKubernetesJWT_B = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImNvbnN1bC1pZHAtdG9rZW4tcmV2aWV3LWFjY291bnQtdG9rZW4tbTYyZHMiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiY29uc3VsLWlkcC10b2tlbi1yZXZpZXctYWNjb3VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijc1ZTNjYmVhLTRiNTYtMTFlOS1hYzRiLTcwOGIxMTgwMWNiZSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmNvbnN1bC1pZHAtdG9rZW4tcmV2aWV3LWFjY291bnQifQ.uMb66tZ8d8gNzS8EnjlkzbrGKc5M-BESwS5B46IUbKfdMtajsCwgBXICytWKQ2X7wfm4QQykHVaElijBlO8QVvYeYzQE0uy75eH9EXNXmRh862YL_Qcy_doPC0R6FQXZW99S5Joc-3riKsq7N-sjEDBshOqyfDaGfan3hxaiV4Bv4hXXWRFUQ9aTAfPVvk1FQi21U9Fbml9ufk8kkk6gAmIEA_o7p-ve6WIhm48t7MJv314YhyVqXdrvmRykPdMwj4TfwSn3pTJ82P4NgSbXMJhwNkwIadJPZrM8EfN5ISpR4EW3jzP3IHtgQxrIovWQ9TQib1Z5zdRaLWaFVm6XaQ"
