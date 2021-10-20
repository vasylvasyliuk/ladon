package ladon_test

import (
	"github.com/ory/ladon"
	"github.com/ory/ladon/manager/memory"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testCases = []struct {
	Policies         []ladon.Policy
	TargetResource   string
	QualifiedActions []ladon.QualifiedAction
	Subject          string
}{
	{
		Policies: []ladon.Policy{
			&ladon.DefaultPolicy{
				ID:        "c4sb3es4meac72ok92gg",
				Subjects:  []string{`users:<local2@company.com>`},
				Effect:    ladon.DenyAccess,
				Resources: []string{`secrets:azure-99:server1`},
				Actions:   []string{`delete`},
			},
			&ladon.DefaultPolicy{
				ID:        `c4sb2lk4meac72ok92g0`,
				Subjects:  []string{`users:<local2@company.com>`},
				Effect:    ladon.AllowAccess,
				Resources: []string{`secrets:azure-99:<.*>`},
				Actions:   []string{`read`, `delete`},
			},
		},
		TargetResource: `secrets:azure-99:server1`,
		QualifiedActions: []ladon.QualifiedAction{
			{Effect: ladon.AllowAccess, Action: "read"},
			{Effect: ladon.DenyAccess, Action: "delete"},
		},
		Subject: `users:<local2@company.com>`,
	},
	{
		Policies: []ladon.Policy{
			&ladon.DefaultPolicy{
				ID:        "first",
				Subjects:  []string{`users:<local3@company.com>`},
				Effect:    ladon.DenyAccess,
				Resources: []string{`secrets:azure-99:server1`},
				Actions:   []string{`<delete|update>`, `create`},
			},
			&ladon.DefaultPolicy{
				ID:        `second`,
				Subjects:  []string{`users:<local3@company.com>`},
				Effect:    ladon.AllowAccess,
				Resources: []string{`secrets:azure-99:<.*>`},
				Actions:   []string{`read`, `create`},
			},
		},
		TargetResource: `secrets:azure-99:server1`,
		QualifiedActions: []ladon.QualifiedAction{
			{Effect: ladon.DenyAccess, Action: "delete"},
			{Effect: ladon.DenyAccess, Action: "update"},
			{Effect: ladon.AllowAccess, Action: "read"},
			{Effect: ladon.DenyAccess, Action: "create"},
		},
		Subject: `users:<local3@company.com>`,
	},
}

func TestGetPermissionsImplicitStable(t *testing.T) {
	for _, testCase := range testCases {
		warden := ladon.Ladon{Manager: memory.NewMemoryManager()}
		for _, p := range testCase.Policies {
			if err := warden.Manager.Create(p); err != nil {
				panic(err)
			}
		}

		for j := 0; j < 100; j++ {
			policySummaryMap, err := warden.GetPermissionsImplicit(testCase.TargetResource)
			assert.NoError(t, err)
			assert.Equal(t, 1, len(policySummaryMap))

			actions, ok := policySummaryMap[testCase.Subject]
			assert.Equal(t, true, ok)
			assert.Equal(t, len(testCase.QualifiedActions), len(actions.Actions))
			for _, qa := range testCase.QualifiedActions {
				assert.Contains(t, actions.Actions, qa)
			}
		}
	}
}
