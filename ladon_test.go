/*
 * Copyright © 2016-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package ladon_test

import (
	"fmt"
	"testing"

	. "github.com/noahhai/ladon"
	. "github.com/noahhai/ladon/manager/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A bunch of exemplary policies
var pols = []Policy{
	&DefaultPolicy{
		ID: "1",
		Description: `This policy allows max, peter, zac and ken to create, delete and get the listed resources,
			but only if the client ip matches and the request states that they are the owner of those resources as well.`,
		Subjects:  []string{"max", "peter", "<zac|ken>"},
		Resources: []string{"myrn:some.domain.com:resource:123", "myrn:some.domain.com:resource:345", "myrn:something:foo:<.+>"},
		Actions:   []string{"<create|delete>", "get"},
		Effect:    AllowAccess,
		Conditions: Conditions{
			"owner": &EqualsSubjectCondition{},
			"clientIP": &CIDRCondition{
				CIDR: "127.0.0.1/32",
			},
		},
	},
	&DefaultPolicy{
		ID:          "2",
		Description: "This policy allows max to update any resource",
		Subjects:    []string{"max"},
		Actions:     []string{"update"},
		Resources:   []string{"<.*>"},
		Effect:      AllowAccess,
	},
	&DefaultPolicy{
		ID:          "3",
		Description: "This policy denies max to broadcast any of the resources",
		Subjects:    []string{"max"},
		Actions:     []string{"broadcast"},
		Resources:   []string{"<.*>"},
		Effect:      DenyAccess,
	},
}

// Some test cases
var cases = []struct {
	description   string
	accessRequest *Request
	expectErr     bool
}{
	{
		description: "should fail because no policy is matching as field clientIP does not satisfy the CIDR condition of policy 1.",
		accessRequest: &Request{
			Subject:  "peter",
			Action:   "delete",
			Resource: "myrn:some.domain.com:resource:123",
			Context: Context{
				"owner":    "peter",
				"clientIP": "0.0.0.0",
			},
		},
		expectErr: true,
	},
	{
		description: "should fail because no policy is matching as the owner of the resource 123 is zac, not peter!",
		accessRequest: &Request{
			Subject:  "peter",
			Action:   "delete",
			Resource: "myrn:some.domain.com:resource:123",
			Context: Context{
				"owner":    "zac",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: true,
	},
	{
		description: "should pass because policy 1 is matching and has effect allow.",
		accessRequest: &Request{
			Subject:  "peter",
			Action:   "delete",
			Resource: "myrn:some.domain.com:resource:123",
			Context: Context{
				"owner":    "peter",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: false,
	},
	{
		description: "should pass because max is allowed to update all resources.",
		accessRequest: &Request{
			Subject:  "max",
			Action:   "update",
			Resource: "myrn:some.domain.com:resource:123",
		},
		expectErr: false,
	},
	{
		description: "should pass because max is allowed to update all resource, even if none is given.",
		accessRequest: &Request{
			Subject:  "max",
			Action:   "update",
			Resource: "",
		},
		expectErr: false,
	},
	{
		description: "should fail because max is not allowed to broadcast any resource.",
		accessRequest: &Request{
			Subject:  "max",
			Action:   "broadcast",
			Resource: "myrn:some.domain.com:resource:123",
		},
		expectErr: true,
	},
	{
		description: "should fail because max is not allowed to broadcast any resource, even empty ones!",
		accessRequest: &Request{
			Subject: "max",
			Action:  "broadcast",
		},
		expectErr: true,
	},
}

func TestLadon(t *testing.T) {
	// Instantiate ladon with the default in-memory store.
	warden := &Ladon{Manager: NewMemoryManager()}

	// Add the policies defined above to the memory manager.
	for _, pol := range pols {
		require.Nil(t, warden.Manager.Create(pol))
	}

	for k, c := range cases {
		t.Run(fmt.Sprintf("case=%d-%s", k, c.description), func(t *testing.T) {

			// This is where we ask the warden if the access requests should be granted
			err := warden.IsAllowed(c.accessRequest)

			assert.Equal(t, c.expectErr, err != nil)
		})
	}
}

func TestLadonEmpty(t *testing.T) {
	// If no policy was given, the warden must return an error!
	warden := &Ladon{Manager: NewMemoryManager()}
	assert.NotNil(t, warden.IsAllowed(&Request{}))
}

var pathCases = []struct {
	resourcePath    string
	permissionPath1 string
	permissionPath2 string
	expectedResult  bool
}{
	{
		"servers:us-east-1:accounting:dc1",
		"servers:<.*>",
		"servers:us-east-1:accounting",
		false,
	},
	{
		"servers:us-east-1:accounting:dc1",
		"servers:us-east-1:accounting",
		"servers:<.*>",
		true,
	},
	{
		"servers:us-east-1:accounting:dc1",
		"servers:us-east-1:accounting",
		"servers:<.*><.*><.*><.*><.*><.*>:dc1",
		false,
	},
	{
		"servers:us-east-1:departments:accounting:dc1",
		"servers:us-east-1:accounting",
		"servers:<.*><.*><.*><.*><.*><.*>:departments",
		true,
	},
	{
		"servers:us-east-1:departments:servers:dc1",
		"<.*>servers",
		"<.*>departments",
		true,
	},
}

func TestLadonGetSpecificPath(t *testing.T) {

	for k, c := range pathCases {
		t.Run(fmt.Sprintf("case=%d:(%s):(%s)-(%s)", k, c.resourcePath, c.permissionPath1, c.permissionPath2), func(t *testing.T) {
			p1 := PolicySummary{
				Resource: c.permissionPath1,
				Actions: []QualifiedAction{
					QualifiedAction{
						Effect: "allow",
						Action: "view",
					},
				},
			}

			p2 := PolicySummary{
				Resource: c.permissionPath2,
				Actions: []QualifiedAction{
					QualifiedAction{
						Effect: "allow",
						Action: "view",
					},
				},
			}
			assert.Equal(t, c.expectedResult, GetMoreSpecificPath(c.resourcePath, p1, p2))
		})
	}

}

var implicitPermissionCases = []struct {
	resource        string
	policies        []Policy
	expectedSummary PolicySummaryMap
}{
	{
		"servers:us-east-1:accounting:server1",
		[]Policy{
			&DefaultPolicy{
				Resources: []string{
					"servers:otherserver",
					"servers:us-east-1:<.*>",
				},
				Effect: "allow",
				Actions: []string{
					"<.*>",
				},
				Subjects: []string{
					"users:noah",
				},
			},
		},
		PolicySummaryMap{
			"users:noah": PolicySummary{
				Actions: []QualifiedAction{
					QualifiedAction{
						Action: "<.*>",
						Effect: "allow",
					},
				},
			},
		},
	},

	{
		"servers:us-east-1:departments:accounting:server1",
		[]Policy{
			&DefaultPolicy{
				Resources: []string{
					"servers:otherserver",
					"servers:us-east-1:<.*>",
				},
				Effect: "allow",
				Actions: []string{
					"<get|post>",
					"delete",
				},
				Subjects: []string{
					"users:noah",
					"users:ben",
				},
			},
			&DefaultPolicy{
				Resources: []string{
					"servers:otherserver",
					"servers:us-east-1:departments:<.*>",
				},
				Effect: "deny",
				Actions: []string{
					"<get|post>",
				},
				Subjects: []string{
					"users:ben",
				},
			},
		},
		PolicySummaryMap{
			"users:noah": PolicySummary{
				Actions: []QualifiedAction{
					QualifiedAction{
						Action: "get",
						Effect: "allow",
					},
					QualifiedAction{
						Action: "post",
						Effect: "allow",
					},
					QualifiedAction{
						Action: "delete",
						Effect: "allow",
					},
				},
			},
			"users:ben": PolicySummary{
				Actions: []QualifiedAction{
					QualifiedAction{
						Action: "get",
						Effect: "deny",
					},
					QualifiedAction{
						Action: "post",
						Effect: "deny",
					},
					QualifiedAction{
						Action: "delete",
						Effect: "allow",
					},
				},
			},
		},
	},

	{
		"servers:us-east-1:departments:accounting:server1",
		[]Policy{
			&DefaultPolicy{
				Resources: []string{
					"servers:<.*>server1",
				},
				Effect: "allow",
				Actions: []string{
					"<.*>",
				},
				Subjects: []string{
					"users:kevin",
				},
			},
			&DefaultPolicy{
				Resources: []string{
					"servers:<.*>server1",
				},
				Effect: "allow",
				Actions: []string{
					"<get|post>",
					"delete",
				},
				Subjects: []string{
					"users:noah",
					"users:ben",
				},
			},
			&DefaultPolicy{
				Resources: []string{
					"servers:us-east-1:departments:<.*>",
				},
				Effect: "deny",
				Actions: []string{
					"<get|post>",
				},
				Subjects: []string{
					"users:ben",
				},
			},
		},
		PolicySummaryMap{
			"users:noah": PolicySummary{
				Actions: []QualifiedAction{
					QualifiedAction{
						Action: "get",
						Effect: "allow",
					},
					QualifiedAction{
						Action: "post",
						Effect: "allow",
					},
					QualifiedAction{
						Action: "delete",
						Effect: "allow",
					},
				},
			},
			"users:ben": PolicySummary{
				Actions: []QualifiedAction{
					QualifiedAction{
						Action: "get",
						Effect: "deny",
					},
					QualifiedAction{
						Action: "post",
						Effect: "deny",
					},
					QualifiedAction{
						Action: "delete",
						Effect: "allow",
					},
				},
			},
			"users:kevin": PolicySummary{
				Actions: []QualifiedAction{
					QualifiedAction{
						Action: "<.*>",
						Effect: "allow",
					},
				},
			},
		},
	},
}

func TestLadonGetPermissionImplicit(t *testing.T) {
	warden := &Ladon{Manager: NewMemoryManager()}

	for k, c := range implicitPermissionCases {
		t.Run(fmt.Sprintf("case=%d:(%s)", k, c.resource), func(t *testing.T) {
			summary, err := warden.GetPermissionsImplicitInternal(c.resource, c.policies)
			// need to clear PolicySummary.Resource since not serialized anyway and only used internally
			for k, v := range summary {
				v.Resource = ""
				summary[k] = v
			}
			assert.Nil(t, err)
			assert.Equal(t, c.expectedSummary, summary)
		})
	}
}
