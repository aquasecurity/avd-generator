---
title: Code Injection
id: TRC-3
aliases: [
    "/tracee/trc3"
]
source: Tracee
icon: aqua
shortName: Code Injection
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

### Code Injection
Possible code injection into another process

### MITRE ATT&CK
Defense Evasion: Process Injection


### Rego Policy
```
package tracee.TRC_3

import data.tracee.helpers

__rego_metadoc__ := {
    "id": "TRC-3",
    "version": "0.1.0",
    "name": "Code injection",
    "description": "Possible code injection into another process",
    "tags": ["linux", "container"],
    "properties": {
        "Severity": 3,
        "MITRE ATT&CK": "Defense Evasion: Process Injection",
    }
}

eventSelectors := [
    {
        "source": "tracee",
        "name": "ptrace"
    },
    {
        "source": "tracee",
        "name": "security_file_open"
    },
    {
        "source": "tracee",
        "name": "process_vm_writev"
    }
]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}


tracee_match {
    input.eventName == "ptrace"
    arg_value = helpers.get_tracee_argument("request")
    arg_value == "PTRACE_POKETEXT"
}

tracee_match = res {
    input.eventName == "security_file_open"
    flags = helpers.get_tracee_argument("flags")

    helpers.is_file_write(flags)

    pathname := helpers.get_tracee_argument("pathname")

    regex.match(`/proc/(?:\d.+|self)/mem`, pathname)

    res := {
        "file flags": flags,
        "file path": pathname,
    }
}

tracee_match {
    input.eventName == "process_vm_writev"
    dst_pid = helpers.get_tracee_argument("pid")
    dst_pid != input.processId
}
```
