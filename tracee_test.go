package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_generateTraceePages(t *testing.T) {
	postsDir, _ := ioutil.TempDir("", "Test_generateTraceePages-*")
	defer func() {
		_ = os.RemoveAll(postsDir)
	}()
	require.NoError(t, generateTraceePages("goldens/tracee-sigs", postsDir, fakeClock{}))

	gotFiles, err := GetAllFiles(postsDir)
	require.NoError(t, err)
	assert.Equal(t, 2, len(gotFiles))

	// check for various files and contents
	got, err := ioutil.ReadFile(filepath.Join(postsDir, "TRC2.md"))
	require.NoError(t, err)

	assert.Equal(t, `---
title: "Anti-Debugging"
date: 2020-11-18T14:32:34-08:00
draft: false

avd_page_type: tracee_page
---

### TRC-2
#### Anti-Debugging

### Severity
#### High

### Description
Process uses anti-debugging technique to block debugger

### MITRE ATT&CK
Defense Evasion: Execution Guardrails

### Version
0.1.0

### Rego Policy
`+"```"+`
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
`+"```"+`
`, string(got))

	got, err = ioutil.ReadFile(filepath.Join(postsDir, "TRC3.md"))
	require.NoError(t, err)

	assert.Equal(t, `---
title: "Code injection"
date: 2020-11-18T14:32:34-08:00
draft: false

avd_page_type: tracee_page
---

### TRC-3
#### Code injection

### Severity
#### High

### Description
Possible code injection into another process

### MITRE ATT&CK
Defense Evasion: Process Injection

### Version
0.1.0

### Rego Policy
`+"```"+`
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

    `+"regex.match(`/proc/(?:\\d.+|self)/mem`, pathname)"+`

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
`+"```"+`
`, string(got))
}
