---
title: Anti Debugging
id: TRC-2
aliases: [
    "/tracee/trc2"
]
source: Tracee
icon: aqua
shortName: Anti Debugging
severity: high
draft: false
version: 0.1.0

category: runsec
date: 2021-04-15T20:55:39Z

remediations:

breadcrumbs: 
  - name: Tracee
    path: /tracee
  - name: Defense Evasion
    path: /tracee/defense-evasion

avd_page_type: avd_page
---

### Anti Debugging
Process uses anti-debugging technique to block debugger

### MITRE ATT&CK
Defense Evasion: Execution Guardrails


### Rego Policy
```
package tracee.TRC_2

__rego_metadoc__ := {
    "id": "TRC-2",
    "version": "0.1.0",
    "name": "Anti-Debugging",
    "description": "Process uses anti-debugging technique to block debugger",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
    }
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "ptrace"
	}
}

tracee_match {
    input.eventName == "ptrace"
    arg := input.args[_]
    arg.name == "request"
    arg.value == "PTRACE_TRACEME"
}
```
