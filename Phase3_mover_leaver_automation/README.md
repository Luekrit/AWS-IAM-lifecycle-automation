## Phase 3: Mover & Leaver Lifecycle Automation

### Objective

Automate role changes (**Movers**) and offboarding (**Leavers**) so that access always matches the current job, and leavers lose **all** access immediately while their record is kept for audit.

---

### Files

| File | Purpose |
|---|---|
| `mover_leaver.csv` | Input: `username,action,role,ticket` (`action` is `move` or `leave`) |
| `mover_leaver.py` | Processes every row in the CSV |
| `mover.py` | Processes only the `move` rows |
| `leaver.py` | Processes only the `leave` rows; `--purge` deletes leavers after the retention period |

```csv
username,action,role,ticket
bob.dev,move,security-analyst,HR-1004
carol.sec,leave,,HR-1005
```

---

### Mover (e.g. Bob: developer → security analyst)

1. Refuses if the user does not exist (new people must go through the Joiner), is outside `/iamlab/`, or is a terminated leaver.
2. **Removes the old access first**: all groups, any directly attached or inline policies left over from manual changes. The user never holds old and new access together.
3. Adds the new role's group.
4. **Revokes credentials issued under the old role**: access keys deactivated, password reset forced.
5. Updates the `department`/`role`/`ticket` tags. The ABAC policies read `department`, so this also moves his data access.

### Leaver, stage 1: disable (immediately)

Order matters:

1. **Deny-all quarantine policy first.** An explicit deny overrides every allow, so even a credential we have not reached yet is useless.
2. Delete the console password; deactivate access keys, SSH keys, signing certificates and service-specific credentials.
3. Remove groups and all other policies.
4. Tag `lifecycle-status=terminated` with the date and ticket.

The user record is **kept** for the retention period (30 days in this lab) for investigations and audit.

### Leaver, stage 2: purge (after retention)

```bash
python leaver.py --purge --profile iamlab           # dry run: shows who is due
python leaver.py --purge --profile iamlab --apply
```

Deletes every credential type (including MFA devices), the quarantine policy, and then the user. Only users under `/iamlab/` tagged `terminated` and older than the retention period are touched.

---

### How to run

```bash
python ../Phase2_Joiner_automation/validate_csv.py mover_leaver.csv --schema lifecycle
python mover_leaver.py --profile iamlab              # dry run
python mover_leaver.py --profile iamlab --apply      # asks you to type 'apply'
```

Results go to the console and to `audit-logs/<date>.jsonl`. Check afterwards with the Phase 4 access review, which flags any leaver who still has access.

![Mover result](screenshot/Screenshot%202025-07-31%20220226.png)

> Screenshots are from the original 2025 run (identifiers redacted).

---

### Practices demonstrated

- **Least privilege across role changes**: old access removed before new access is granted
- **Immediate, complete revocation** for leavers, independent of the order in which credentials are cleaned up
- **Retention before deletion**, so the identity record is available for audit
- **Traceability**: every action carries the actor ARN and ticket number
- **Guardrails**: dry run by default, typed confirmation, managed-path restriction
