package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

type RelatedAttackPattern struct {
	CAPECID int
}

// The RelatedAttackPatternsType complex type contains references to attack patterns associated with this weakness. The association implies those attack patterns may be applicable if an instance of this weakness exists. Each related attack pattern is identified by a CAPEC identifier.
type RelatedAttackPatternsType struct {
	RelatedAttackPattern []RelatedAttackPattern
}

type Mitigation struct {
	Phase       []PhaseEnumeration
	Strategy    MitigationStrategyEnumeration
	Description StructuredTextType
}

// May be one of Policy, Requirements, Architecture and Design, Implementation, Build and Compilation, Testing, Documentation, Bundling, Distribution, Installation, System Configuration, Operation, Patching and Maintenance, Porting, Integration, Manufacturing
type PhaseEnumeration string

// May be one of Attack Surface Reduction, Compilation or Build Hardening, Enforcement by Conversion, Environment Hardening, Firewall, Input Validation, Language Selection, Libraries or Frameworks, Resource Limitation, Output Encoding, Parameterization, Refactoring, Sandbox or Jail, Separation of Privilege
type MitigationStrategyEnumeration string

// The PotentialMitigationsType complex type is used to describe potential mitigations associated with a weakness. It contains one or more Mitigation elements, which each represent individual mitigations for the weakness. The Phase element indicates the development life cycle phase during which this particular mitigation may be applied. The Strategy element describes a general strategy for protecting a system to which this mitigation contributes. The Effectiveness element summarizes how effective the mitigation may be in preventing the weakness. The Description element contains a description of this individual mitigation including any strengths and shortcomings of this mitigation for the weakness.
//
// The optional Mitigation_ID attribute is used by the internal CWE team to uniquely identify mitigations that are repeated across any number of individual weaknesses. To help make sure that the details of these common mitigations stay synchronized, the Mitigation_ID is used to quickly identify those mitigation elements across CWE that should be identical. The identifier is a string and should match the following format: MIT-1.
type PotentialMitigationsType struct {
	Mitigation []Mitigation
}

// The CommonConsequencesType complex type is used to specify individual consequences associated with a weakness. The required Scope element identifies the security property that is violated. The optional Impact element describes the technical impact that arises if an adversary succeeds in exploiting this weakness. The optional Likelihood element identifies how likely the specific consequence is expected to be seen relative to the other consequences. For example, there may be high likelihood that a weakness will be exploited to achieve a certain impact, but a low likelihood that it will be exploited to achieve a different impact. The optional Note element provides additional commentary about a consequence.
//
// The optional Consequence_ID attribute is used by the internal CWE team to uniquely identify examples that are repeated across any number of individual weaknesses. To help make sure that the details of these common examples stay synchronized, the Consequence_ID is used to quickly identify those examples across CWE that should be identical. The identifier is a string and should match the following format: CC-1.
type CommonConsequencesType struct {
	Consequence []Consequence
}

type Consequence struct {
	Scope  []ScopeEnumeration
	Impact []TechnicalImpactEnumeration
}

// May be one of Modify Memory, Read Memory, Modify Files or Directories, Read Files or Directories, Modify Application Data, Read Application Data, DoS: Crash, Exit, or Restart, DoS: Amplification, DoS: Instability, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory), DoS: Resource Consumption (Other), Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity, Bypass Protection Mechanism, Hide Activities, Alter Execution Logic, Quality Degradation, Unexpected State, Varies by Context, Reduce Maintainability, Reduce Performance, Reduce Reliability, Other
type TechnicalImpactEnumeration string

// May be one of Confidentiality, Integrity, Availability, Access Control, Accountability, Authentication, Authorization, Non-Repudiation, Other
type ScopeEnumeration string

type StructuredTextType []string

type WeaknessType struct {
	ID                    int
	Name                  string
	Description           string
	PotentialMitigations  PotentialMitigationsType
	RelatedAttackPatterns RelatedAttackPatternsType
	CommonConsequences    CommonConsequencesType
	ExtendedDescription   StructuredTextType
}

func AddCWEInformation(bp *VulnerabilityPost, cweDir string) error {
	b, err := ioutil.ReadFile(filepath.Join(cweDir, fmt.Sprintf("%s.json", bp.Vulnerability.CWEID)))
	if err != nil {
		return err
	}

	var w WeaknessType
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}

	bp.ShortName = strings.ReplaceAll(w.Name, "\\", "\\\\")

	bp.Vulnerability.CWEInfo = w
	return nil
}
