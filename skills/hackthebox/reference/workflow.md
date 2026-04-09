# HackTheBox Workflow — Detailed Steps

## 1. Get Credentials
```bash
python3 ./tools/env-reader.py HTB_USER HTB_PASS ANTHROPIC_API_KEY SLACK_BOT_TOKEN HTB_SLACK_CHANNEL_ID
```
Use `HTB_USER`/`HTB_PASS` from `ENV_VALUES`. Only `AskUserQuestion` if `NOT_SET`.
Slack is enabled when BOTH `SLACK_BOT_TOKEN` and `HTB_SLACK_CHANNEL_ID` are set.

## 2. Check VPN
Only for "Machine" kind of competition -> Verify vpn is running, otherwise download the vpn file from HTB and instruct the user on how to enable it

This skill does NOT start VPN — the user manages it. Check if running:
```bash
ps aux | grep -v grep | grep openvpn && echo "VPN_RUNNING" || echo "VPN_NOT_RUNNING"
```
If not running → `AskUserQuestion` asking user to start it. Do NOT try to start VPN yourself.

## 3. Generate output dirs

```bash
mkdir -p YYMMDD_<name>/{recon,findings,logs,artifacts,reports}
```

## 4. Login hackthebox.com (headed browser, NEVER headless)
Navigate `https://app.hackthebox.com/login`, fill credentials, handle 2FA. Use headed mode + anti-detection flags + realistic viewport + persistent context for `cf_clearance`. If blocked: `reference/cloudflare-bypass.md`. Fallback: HTB API `https://labs.hackthebox.com/api/v4/` with Bearer token.

## 5. If necessary, start the machine
1. Navigate to the requested machine/challenge (or browse and present options via `AskUserQuestion`)
2. Start the machine if not running
3. Save challenge info to `YYMMDD_<name>/challenge-meta.json`

## 6. If necessary, check network connectivity to the machine
Only for those competition that requires machine to be started and connected through VPN

```bash
ping -c 3 {target_ip}
curl -s --connect-timeout 5 http://{target_ip}/
curl -s --connect-timeout 5 ifconfig.me
```
If any fails: check VPN, retry up to 3 times → `AskUserQuestion` if still failing.

Pre-configure `/etc/hosts`:
```bash
grep -v "{target_ip}" /etc/hosts | grep -v "{name}.htb" > /tmp/hosts.clean
sudo cp /tmp/hosts.clean /etc/hosts
echo "{target_ip} {name}.htb {name}" | sudo tee -a /etc/hosts
```
Add more entries if coordinator discovers additional vhosts later.

Record start time:
```bash
date -u +%Y-%m-%dT%H:%M:%SZ > YYMMDD_<name>/logs/start_time.txt
```

## 7. Spawn and manage coordinator agent pool

**Strict 1:1 mapping**: One coordinator agent per challenge, never shared.

**Pool management** (queue-based with cap N, default: 3 max concurrent):
1. Maintain a queue of challenges to solve
2. Start with min(N, total_challenges) coordinator agents from the queue
3. Each agent solves exactly ONE challenge, then terminates
4. When an agent completes, immediately spawn the next challenge from the queue
5. Never exceed N agents running simultaneously

**Example**: 5 challenges with max N=3:
- T0: Queue=[1,2,3,4,5]. Spawn agents for 1, 2, 3. Running: [1,2,3]
- T1: Agent 1 completes. Spawn agent for 4. Running: [2,3,4]. Queue=[5]
- T2: Agent 2 completes. Spawn agent for 5. Running: [3,4,5]. Queue=[]
- T3: Agents 3,4,5 complete. All done.

**Agent responsibility** (one challenge only):
- Analyze TARGET, plan exploitation
- Spawn executor agents (each in separate browser tab) as needed
- Extract flags, submit to HTB platform
- Generate completion report → `{OUTPUT_DIR}/reports/completion-report.md`
- Write stats → `{OUTPUT_DIR}/stats.json`
- Terminate when challenge is complete

Each agent writes to its own `OUTPUT_DIR` (unique per challenge).

**Reference**: See [coordinator-spawn.md](coordinator-spawn.md) for coordinator spawn prompt template.

## 8. Post-Solve Loop (parent orchestrator)

**The parent orchestrator handles skill-update and Slack for every completed coordinator.** This guarantees these steps always run, even if a coordinator runs out of context or errors out.

**Hook enforcement** (active in `projects/ctf/`): When a coordinator named `htb-coordinator-*` completes, a `SubagentStop` hook injects a mandatory `/skill-update` reminder into the parent context. `slack-send.py` is **blocked** by a `PreToolUse` hook until `/skill-update` runs and creates `.skill-update-done` in the output dir. See `.claude/hooks/htb-skill-update-gate.sh`.

After each coordinator completes:

1. **Read outputs** — `{OUTPUT_DIR}/reports/completion-report.md` + `{OUTPUT_DIR}/stats.json`
2. **Run `/skill-update`** — pass techniques, lessons learned, and failed approaches from the completion report. Only generalizable patterns, no target-specific data.
3. **Send Slack notification** (if `SLACK_BOT_TOKEN` + `HTB_SLACK_CHANNEL_ID` are set):
   - Compose message per [slack-notifications.md](slack-notifications.md) using completion report + stats + skill-update output
   - Send via `python3 tools/slack-send.py --token "{SLACK_BOT_TOKEN}" --channel "{HTB_SLACK_CHANNEL_ID}" -`
4. **Log completion** to parent console
5. **Spawn next** challenge from queue (if any remain)

If the completion report is missing (coordinator crashed), log a warning and skip skill-update/Slack for that challenge. Do not block the queue.

## Flag Progression (Multi-Flag Machines)

HTB machines are designed as chains — each flag builds on the previous foothold.

1. **User flag first, always.** Establish stable access before attempting root.
2. **From user shell, enumerate for root.** The user context often reveals the root path (sudo -l, groups, SeBackupPrivilege, RODC access, etc.)
3. **Don't skip steps.** Advanced techniques (RODC golden tickets, kernel exploits) require prerequisites that earlier flags provide.
4. **AD machines: enumerate ACLs early.** Run `bloodyAD get writable` and BloodHound. Check ForceChangePassword, GenericWrite (scriptPath hijack), WriteDACL, RBCD paths, SeBackupPrivilege, MachineAccountQuota. These are the most common HTB AD escalation vectors.
5. **Clock skew breaks Kerberos.** If any Kerberos tool fails, check skew and use `faketime` prefix.
6. **Internal subnets need tunneling.** If you find Hyper-V (port 2179), dual NICs, or internal IPs — set up Ligolo-ng or chisel to reach internal hosts.
