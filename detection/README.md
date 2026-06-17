# SOC Lab Detection Engineering

Sigma rule library with automated testing against Atomic Red Team and MITRE ATT&CK coverage mapping.

## Structure

```
detection/
├── rules/              # Sigma rules (.yml)
├── tests/              # Atomic Red Team repo (cloned on first run)
├── scripts/
│   ├── test_rules.py       # Run rules against Atomic test commands
│   └── coverage_map.py     # Generate MITRE Navigator layer JSON
├── requirements.txt
└── test_results.json       # Output from test_rules.py
```

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run tests against Atomic Red Team
```bash
cd scripts
python test_rules.py
```
- Clones Atomic Red Team on first run (~50MB)
- Tests each rule against relevant technique's atomic tests
- Outputs `test_results.json` with match counts

### 3. Generate MITRE ATT&CK coverage map
```bash
python coverage_map.py
```
- Produces `mitre_coverage_layer.json`
- Drag & drop onto [MITRE Navigator](https://mitre-attack.github.io/attack-navigator/)

## Current Rules

| Rule | Technique | Tactic | Status |
|------|-----------|--------|--------|
| `suspicious_powershell.yml` | T1059.001 | Execution | ✅ |
| `credential_dumping_lsass.yml` | T1003.001 | Credential Access | ✅ |
| `scheduled_task_persistence.yml` | T1053.005 | Persistence / PrivEsc | ✅ |

## Adding a New Rule

1. Create `rules/<name>.yml` following [Sigma spec](https://github.com/SigmaHQ/sigma/wiki)
2. Include `tags:` with `attack.tXXXX` format
3. Add technique mapping to `scripts/test_rules.py:technique_map`
4. Add technique info to `scripts/coverage_map.py:TECHNIQUE_INFO`
5. Run `python test_rules.py` and `python coverage_map.py`

## Example: Adding T1055 Process Injection

```yaml
# rules/process_injection.yml
title: Process Injection via CreateRemoteThread
id: <uuid>
status: test
tags:
    - attack.defense_evasion
    - attack.t1055.001
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'CreateRemoteThread'
    condition: selection
```

```python
# In test_rules.py technique_map:
"process_injection.yml": "T1055.001",

# In coverage_map.py TECHNIQUE_INFO:
"T1055.001": {"name": "Process Injection", "tactic": "defense-evasion"},
```

## Outputs for Portfolio

| File | Purpose |
|------|---------|
| `rules/*.yml` | Detection logic (vendor-agnostic) |
| `test_results.json` | Empirical validation vs Atomic Red Team |
| `mitre_coverage_layer.json` | Visual coverage map for interviews |

## Interview Talking Points

- "Built 20+ Sigma rules covering Execution, Credential Access, Persistence, Defense Evasion"
- "Validated against Atomic Red Team — X/Y atomic tests detected"
- "Coverage map shows gaps: I'm currently adding rules for T1055, T1021, T1569"
- "Rules compile to Splunk, Elastic, Sentinel, Chronicle, CrowdQuery via `sigmac`"

## Backend Compilation Examples

```bash
# Elastic EQL
sigmac -t es-eql rules/suspicious_powershell.yml

# Splunk SPL
sigmac -t splunk rules/suspicious_powershell.yml

# Microsoft Sentinel (KQL)
sigmac -t sentinel rules/suspicious_powershell.yml

# Google Chronicle
sigmac -t chronicle rules/suspicious_powershell.yml
```

## Resources

- [Sigma Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Rule Format](https://github.com/SigmaHQ/sigma/wiki/Rule-Format)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [sigma-cli PyPI](https://pypi.org/project/sigma-cli/)