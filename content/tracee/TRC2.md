---
title: "Anti-Debugging"
date: 2020-11-18T14:32:34-08:00
draft: false

avd_page_type: tracee_page
---

### TRC-2
#### Anti-Debugging

### Severity
#### HIGH

### Description
Process uses anti-debugging technique to block debugger

### MITRE ATT&CK
Defense Evasion: Execution Guardrails

### Version
0.1.0

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