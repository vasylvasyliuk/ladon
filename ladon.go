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

package ladon

import (
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
)

// Ladon is an implementation of Warden.
type Ladon struct {
	Manager     Manager
	Matcher     matcher
	AuditLogger AuditLogger
}

func (l *Ladon) matcher() matcher {
	if l.Matcher == nil {
		l.Matcher = DefaultMatcher
	}
	return l.Matcher
}

func (l *Ladon) auditLogger() AuditLogger {
	if l.AuditLogger == nil {
		l.AuditLogger = DefaultAuditLogger
	}
	return l.AuditLogger
}

// IsAllowed returns nil if subject s has permission p on resource r with context c or an error otherwise.
func (l *Ladon) IsAllowed(r *Request) (err error) {
	policies, err := l.Manager.FindRequestCandidates(r)
	if err != nil {
		return err
	}

	// Although the manager is responsible of matching the policies, it might decide to just scan for
	// subjects, it might return all policies, or it might have a different pattern matching than Golang.
	// Thus, we need to make sure that we actually matched the right policies.
	return l.DoPoliciesAllow(r, policies)
}

// DoPoliciesAllow returns nil if subject s has permission p on resource r with context c for a given policy list or an error otherwise.
// The IsAllowed interface should be preferred since it uses the manager directly. This is a lower level interface for when you don't want to use the ladon manager.
func (l *Ladon) DoPoliciesAllow(r *Request, policies []Policy) (err error) {
	var allowed = false
	var deciders = Policies{}

	// Iterate through all policies
	for _, p := range policies {
		// Does the action match with one of the policies?
		// This is the first check because usually actions are a superset of get|update|delete|set
		// and thus match faster.
		if pm, err, _ := l.matcher().Matches(p, p.GetActions(), r.Action, true); err != nil {
			return errors.WithStack(err)
		} else if !pm {
			// no, continue to next policy
			continue
		}

		// Does the subject match with one of the policies?
		// There are usually less subjects than resources which is why this is checked
		// before checking for resources.
		if sm, err, _ := l.matcher().Matches(p, p.GetSubjects(), r.Subject, true); err != nil {
			return err
		} else if !sm {
			// no, continue to next policy
			continue
		}

		// Does the resource match with one of the policies?
		if rm, err, _ := l.matcher().Matches(p, p.GetResources(), r.Resource, true); err != nil {
			return errors.WithStack(err)
		} else if !rm {
			// no, continue to next policy
			continue
		}

		// Are the policies conditions met?
		// This is checked first because it usually has a small complexity.
		if !l.passesConditions(p, r) {
			// no, continue to next policy
			continue
		}

		// Is the policies effect deny? If yes, this overrides all allow policies -> access denied.
		if !p.AllowAccess() {
			deciders = append(deciders, p)
			l.auditLogger().LogRejectedAccessRequest(r, policies, deciders)
			return errors.WithStack(ErrRequestForcefullyDenied)
		}

		allowed = true
		deciders = append(deciders, p)
	}

	if !allowed {
		l.auditLogger().LogRejectedAccessRequest(r, policies, deciders)
		return errors.WithStack(ErrRequestDenied)
	}

	l.auditLogger().LogGrantedAccessRequest(r, policies, deciders)
	return nil
}

func (l *Ladon) GetPermissionsExplicit(resource string, policies []Policy) (Policies, error) {
	var matchingPolicies = Policies{}

	// Iterate through all policies
	for _, p := range policies {

		isMatch := false
		// Need exact matches here (explicit)
		for _, res := range p.GetResources() {
			if res == resource {
				isMatch = true
			}
		}
		if !isMatch {
			continue
		}
		matchingPolicies = append(matchingPolicies, p)
	}
	return matchingPolicies, nil
}

func (l *Ladon) GetPermissionsImplicit(resource string, policies []Policy) (PolicySummaryMap, error) {
	var matchingPolicies = Policies{}
	var matchingPaths = make(map[string]string)
	var effectivePolicies = PolicySummaryMap{}

	// Iterate through all policies
	for _, p := range policies {
		// Does the resource match with the policy?
		if rm, err, match := l.matcher().Matches(p, p.GetResources(), resource, true); err != nil {
			return effectivePolicies, errors.WithStack(err)
		} else if !rm {
			// no, continue to next policy
			continue
		} else {
			matchingPaths[p.GetID()] = match
		}
		matchingPolicies = append(matchingPolicies, p)
	}

	// TODO : group by subjects
	for _, p := range policies {
		currentPath, ok := matchingPaths[p.GetID()]
		if !ok {
			return nil, errors.New("error determining relevant resource in implicit permissions calculation")
		}
		for _, subject := range p.GetSubjects() {
			if currentPol, exists := effectivePolicies[subject]; exists {
				for _, actionNewAll := range p.GetActions() {
					effectNew := p.GetEffect()
					for i, actionNew := range trypSplitActionIfRegex(actionNewAll) {

						for _, actionCurrent := range currentPol.Actions {
							if actionCurrent.Action == actionNew {
								if actionCurrent.Effect == effectNew {
									newPolSummary := p.ToSummary(currentPath)
									if GetMoreSpecificPath(currentPath, newPolSummary, currentPol) {
										effectivePolicies[subject] = newPolSummary
									}
								} else {
									// at least one is deny, which trumps
									effectivePolicies[subject].Actions[i].Effect = "deny"
								}
							} else {
								currentPol.Actions = append(currentPol.Actions, QualifiedAction{Action: actionNew, Effect: effectNew})
							}
						}
					}
				}

			} else {
				effectivePolicies[subject] = p.ToSummary(currentPath)
			}
		}
	}
	return effectivePolicies, nil
}

func trypSplitActionIfRegex(action string) []string {
	if action == "" {
		panic("empy action")
	}
	if !actionIsRegex(action) || !actionIsPlainRegex(action) {
		return []string{
			action,
		}
	}
	return strings.Split(action[1:len(action)-1], "|")
}

func actionIsRegex(action string) bool {
	return strings.Contains(action, "<")
}

func actionIsPlainRegex(action string) bool {
	if strings.Contains(action, ".") || strings.Contains(action, "*") || !strings.Contains(action, "|") || action[0:1] != "<" || action[len(action)-1:len(action)] != ">" {
		return false
	}
	return true
}

func GetMoreSpecificPath(resourcePath string, p1 PolicySummary, p2 PolicySummary) bool {
	if strings.Count(p1.Resource, string(p1.GetStartDelimiter())) == 0 && strings.Count(p2.Resource, string(p2.GetStartDelimiter())) == 0 {
		return len(p1.Resource) > len(p2.Resource)
	}
	_, splitRegex1, err := split(p1.Resource, "<>", false)
	if err != nil {
		panic("error determining more specific path: " + err.Error())
	}
	_, splitRegex2, err := split(p2.Resource, "<>", false)
	if err != nil {
		panic("error determining more specific path: " + err.Error())
	}
	if len(splitRegex1)%2 != 0 || len(splitRegex2)%2 != 0 {
		panic("error determining more specific path; invalid resource path")
	}
	var highestMatchIndex1, highestMatchIndex2 int
	var pathElements1, pathElements2 []string
	pathElements1 = make([]string, (len(splitRegex1) + 1/2))
	for i := 0; i < (len(splitRegex1)+1)/2; {
		index := (i + 1) / 2
		pathElements1 = append(pathElements1, string(splitRegex1[index]))
		i++
	}
	lastPathElement1 := pathElements1[len(pathElements1)-1]
	highestMatchIndex1 = strings.LastIndex(resourcePath, lastPathElement1) + len(lastPathElement1)

	pathElements2 = make([]string, (len(splitRegex2) + 1/2))
	for i := 0; i < (len(splitRegex2)+1)/2; {
		index := (i + 1) / 2
		pathElements2 = append(pathElements2, string(splitRegex2[index]))
		i++
	}
	lastPathElement2 := pathElements2[len(pathElements2)-1]
	highestMatchIndex2 = strings.LastIndex(resourcePath, lastPathElement2) + len(lastPathElement2)

	return highestMatchIndex1 > highestMatchIndex2
}

func split(data string, delimiters string, atEOF bool) (advance int, token []byte, err error) {
	dataByte := []byte(data)
	i := strings.IndexAny(data, string(delimiters))
	switch {
	case i < 0 && !atEOF:
		return 0, nil, nil
	case i < 0 && atEOF:
		i = len(dataByte)
	case i == 0:
		_, i = utf8.DecodeRune(dataByte) // just "i = 1" is fine for ASCII
	}
	return i, dataByte[:i], nil
}

func (l *Ladon) passesConditions(p Policy, r *Request) bool {
	for key, condition := range p.GetConditions() {
		if pass := condition.Fulfills(r.Context[key], r); !pass {
			return false
		}
	}
	return true
}
