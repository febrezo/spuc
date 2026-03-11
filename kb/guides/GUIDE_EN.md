# STIX Pattern Interpretation Guide by Observable Type

## Objective

This document organizes the STIX patterns by **observable type** and explains, in a way that is useful for an analyst or another AI agent:

1. **What kind of information they attempt to select or detect**
2. **Which STIX observables and attributes are involved**
3. **Concrete examples**, using the provided patterns, with a descriptive explanation of what each one is intended to detect

---

# 0. Observation Expression Qualifiers (critical section)

This section is specific to STIX 2.1 observation-level qualifiers and should be read before using temporal logic in rules.

## STIX 2.1 semantic rules

- Qualifiers apply to an **observation expression** (or to a previously qualified observation expression).
- An observation expression **must not contain more than one qualifier of the same type**.
- Qualifiers covered here:
  - `REPEATS x TIMES`
  - `WITHIN x SECONDS`
  - `START t'...' STOP t'...'`

### `REPEATS x TIMES`

- Means the observation expression must match at least `x` times.
- Conceptually, it is shorthand for repeating the same observation expression with `AND` (`x-1` additional times).
- Important: this is cardinality on different observations, not just a textual copy of the same predicate.

### `WITHIN x SECONDS`

- All observations matched by the qualified expression must occur inside the specified time window.
- Semantically, this is a correlation window, not just a field filter.

### `START t'...' STOP t'...'`

- Matches observations with observation time `>= START` and `< STOP`.
- Both timestamps are STIX timestamp literals (`t'...'`).

## Current SPUC baseline (runtime behavior)

- `EQL`
  - `FOLLOWEDBY`: supported via `sequence`.
  - `WITHIN` on `FOLLOWEDBY`: lowered to `sequence with maxspan=...`.
  - `REPEATS` in plain where-clause: advisory-only (status usually downgraded to `partial`).
  - `WITHIN` in plain where-clause: advisory-only.
  - `START/STOP`: mapped as `@timestamp` filter.
- `KQL`
  - `START/STOP`: mapped as `Timestamp` filter.
  - `REPEATS` and `WITHIN` in plain where-clause: advisory-only.
  - `FOLLOWEDBY`: unsupported in baseline.
- `Sigma`
  - `REPEATS`: advisory-only in baseline.
  - `WITHIN` and `START/STOP`: unsupported in baseline.
  - `FOLLOWEDBY`: unsupported in baseline.
- `Snort`, `Suricata`, `YARA`
  - Observation qualifiers (`REPEATS/WITHIN/START STOP`) are unsupported in baseline.

Note: use runtime output (`runtime_status`, `summary`, `notes`) as source of truth for semantic fidelity.

---

# 0.1 Hashes and literal semantics (reference)

This section is explicit because hash/literal interpretation directly impacts semantic fidelity.

## Hash algorithms used in patterns

- `MD5`
- `SHA-1`
- `SHA-256`
- `SHA-512`
- `SHA3-256`
- `SHA3-512`
- `SSDEEP`
- `TLSH`

Use exact algorithm names in paths such as:

- `file:hashes.'SHA-256'`
- `artifact:hashes.MD5`

Do not treat algorithms as interchangeable (`SHA-1` is not `SHA-256`).

## Literal forms and normalization

STIX literals used in SPUC normalization:

- `string`: `'text'`
- `binary` (base64): `b'...'`
- `hex`: `h'...'`
- `timestamp`: `t'2016-06-01T00:00:00Z'`

For `artifact:payload_bin`:

- Plain strings are interpreted as raw bytes.
- `b'...'` is base64-decoded to bytes.
- `h'...'` is decoded as hex bytes.

Important non-equivalence:

- `artifact:payload_bin = 'QUJD'` is not equivalent to `artifact:payload_bin = b'QUJD'`.

# 1. Detection on processes (`process`)

## What kinds of things it can detect

Patterns based on `process` are used to detect **program execution, execution context, and relationships between processes**. They are especially useful for:

- Identifying specific processes or known binaries
- Detecting suspicious command lines
- Observing processes created within a time range
- Detecting hidden processes
- Detecting processes launched from unusual directories
- Analyzing which parent process launched another process
- Detecting execution sequences, such as one action followed by another within a few seconds

## Observables and attributes involved

### Main observable
- `process`

### Attributes used
- `process:pid`
- `process:is_hidden`
- `process:cwd`
- `process:created_time`
- `process:command_line`
- `process:name`
- `process:image_ref.name`
- `process:image_ref.hashes.'SHA-256'`
- `process:parent_ref.command_line`

### What information they try to select
- Process identity
- Execution path or context
- Execution parameters
- Underlying binary
- Executable hash
- Relationship with the parent process
- Temporal order between processes

## Examples

### Simple process identification
- `[process:pid = 4]`  
  Looks for the process with exact PID `4`, typically useful to identify a specific system process.

- `[process:pid > 1000]`  
  Looks for processes with a high PID, useful to narrow down to more recent processes or those outside the core system set.

- `[process:is_hidden = true]`  
  Attempts to detect processes marked as hidden, which may indicate evasion or suspicious behavior.

- `[process:name = 'powershell.exe']`  
  Selects processes whose name is exactly `powershell.exe`.

- `[process:name = 'cmd.exe']`  
  Selects processes whose name is exactly `cmd.exe`.

- `[process:name LIKE '%.exe']`  
  Selects processes whose name ends in `.exe`.

- `[process:name MATCHES '(?i)^powershell(\.exe)?$']`  
  Looks for processes whose name matches exactly `powershell` or `powershell.exe`, case-insensitively.

### Binary associated with the process
- `[process:image_ref.name = 'powershell.exe']`  
  Looks for processes whose referenced executable is named `powershell.exe`.

- `[process:image_ref.name LIKE '%.exe']`  
  Looks for processes whose associated binary ends in `.exe`.

- `[process:image_ref.hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']`  
  Looks for processes whose associated executable has that exact SHA-256, useful for hunting a known sample.

### Execution context and metadata
- `[process:cwd LIKE 'C:\\Users\\%\\AppData\\%']`  
  Looks for processes executed from directories under `AppData`, common in malware or binaries launched from user-space paths.

- `[process:created_time >= t'2025-01-01T00:00:00Z']`  
  Looks for processes created on or after that date.

### Suspicious command lines
- `[process:command_line LIKE '%powershell%' AND process:command_line LIKE '%-enc%']`  
  Looks for PowerShell with encoded arguments, a common sign of obfuscation.

- `[process:command_line LIKE '%rundll32%' AND process:command_line LIKE '%javascript:%']`  
  Looks for the use of `rundll32` with `javascript:`, a classic LOLBin abuse pattern.

- `[process:command_line LIKE '%regsvr32%' AND process:command_line LIKE '%scrobj.dll%']`  
  Looks for abuse of `regsvr32` to load scripts or components in a suspicious way.

- `[process:command_line LIKE '%mshta%' AND process:command_line LIKE '%http%']`  
  Looks for `mshta` accessing HTTP resources, useful for detecting remote execution of HTA files or scripts.

- `[process:command_line LIKE '%certutil%' AND process:command_line LIKE '%-decode%']`  
  Looks for use of `certutil` to decode content, a common technique to reconstruct payloads.

- `[process:command_line LIKE '%powershell%' AND process:command_line LIKE '%DownloadString%']`  
  Looks for PowerShell downloading remote content via `DownloadString`.

- `[process:command_line MATCHES '(?i)^.*powershell(\.exe)?\s+.*DownloadString.*$']`  
  A more precise regex variant to detect PowerShell using `DownloadString`.

- `[process:command_line LIKE '%cmd.exe%' AND process:command_line LIKE '%powershell%' AND process:command_line LIKE '%-w hidden%']`  
  Looks for chained execution where `cmd.exe` launches PowerShell in hidden mode.

- `[process:command_line MATCHES '(?i)^.*cmd(\.exe)?\s+/c\s+.*powershell(\.exe)?\s+.*-w\s+hidden.*$']`  
  A more structured regex version of the previous case.

- `[process:command_line LIKE '%certutil%' AND process:command_line LIKE '%-urlcache%' AND process:command_line LIKE '%-f%' AND process:command_line LIKE '%.exe%']`  
  Looks for `certutil` being used to forcibly download an `.exe`.

- `[process:command_line MATCHES '(?i)^.*certutil(\.exe)?\s+.*-urlcache\s+.*-f\s+.*https?://.+\s+.+\.exe.*$']`  
  A stricter regex variant for executable downloads with `certutil`.

- `[process:command_line LIKE '%rundll32%' AND process:command_line LIKE '%javascript:%' AND process:command_line LIKE '%mshtml,RunHTMLApplication%']`  
  Looks for the classic script execution pattern using `rundll32` and `RunHTMLApplication`.

- `[process:command_line MATCHES '(?i)^.*rundll32(\.exe)?\s+.*javascript:.*mshtml,RunHTMLApplication.*$']`  
  A stricter regex version of the previous pattern.

### Parent process
- `[process:parent_ref.command_line LIKE '%winword%']`  
  Looks for processes whose parent was launched from Word.

- `[process:parent_ref.command_line LIKE '%excel%']`  
  Looks for processes whose parent was launched from Excel.

- `[process:parent_ref.command_line LIKE '%outlook%']`  
  Looks for processes whose parent was launched from Outlook.

### Temporal sequences
- `[process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachine Root$'] FOLLOWEDBY [process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachineTrustedPublisher$'] WITHIN 300 SECONDS`  
  Attempts to detect a sequence of two commands related to certificate installation, executed within 300 seconds.

---

# 2. Detection on registry keys (`windows-registry-key`)

## What kinds of things it can detect

Patterns on `windows-registry-key` make it possible to detect **persistence, malicious configuration, service manipulation, and suspicious changes in the Windows registry**.

## Observables and attributes involved

### Main observable
- `windows-registry-key`

### Attributes used
- `windows-registry-key:key`
- `windows-registry-key:modified_time`
- `windows-registry-key:number_of_subkeys`
- `windows-registry-key:values[*].name`
- `windows-registry-key:values[*].data`
- `windows-registry-key:values[*].data_type`

### What information they try to select
- Exact key name
- Key hierarchy or family of keys
- Modification timestamp
- Number of subkeys
- Registry value names
- Data stored in the values
- Type of stored data

## Examples

- `[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\CryptoLocker\\Files']`  
  Looks for a specific key associated with CryptoLocker.

- `[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\\CryptoLocker_0388']`  
  Looks for an exact persistence entry under `Run`.

- `[windows-registry-key:key LIKE 'HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\\%']`  
  Looks for any key under `Run`, useful for startup persistence.

- `[windows-registry-key:key MATCHES '^HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet\\\\Services\\\\.+$']`  
  Looks for service keys in HKLM, useful for detecting created or altered services.

- `[windows-registry-key:modified_time >= t'2025-01-01T00:00:00Z']`  
  Looks for keys modified on or after that date.

- `[windows-registry-key:number_of_subkeys > 10]`  
  Looks for keys with many subkeys, useful for spotting unusual or complex structures.

- `[windows-registry-key:values[*].name = 'Start']`  
  Looks for values named `Start`, relevant in service configuration.

- `[windows-registry-key:values[*].name = 'ImagePath']`  
  Looks for `ImagePath` values, relevant to binaries associated with services.

- `[windows-registry-key:values[*].data LIKE '%powershell%']`  
  Looks for registry values containing references to PowerShell.

- `[windows-registry-key:values[*].data LIKE '%rundll32%']`  
  Looks for references to `rundll32` in registry data.

- `[windows-registry-key:values[*].data_type = 'REG_SZ']`  
  Looks for string values.

- `[windows-registry-key:values[*].data_type = 'REG_DWORD']`  
  Looks for DWORD values.

- `[windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\CryptoLocker\\Files' OR windows-registry-key:key = 'HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\\CryptoLocker_0388']`  
  Looks for one of two specific keys associated with the same malicious context.

- `[windows-registry-key:key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%' AND windows-registry-key:values[*].data LIKE '%.exe%']`  
  Looks for persistence under `Run` that points to executables.

---

# 3. Detection on network traffic (`network-traffic`)

## What kinds of things it can detect

Patterns with `network-traffic` make it possible to detect **communications between source and destination, protocols in use, ports involved, and network relationships**. They are the richest way to express network telemetry in STIX.

## Observables and attributes involved

### Main observable
- `network-traffic`

### Attributes used
- `network-traffic:src_ref.type`
- `network-traffic:src_ref.value`
- `network-traffic:dst_ref.type`
- `network-traffic:dst_ref.value`
- `network-traffic:src_port`
- `network-traffic:dst_port`
- `network-traffic:protocols`

### What information they try to select
- Source or destination type (IP, domain)
- Source or destination IP address or value
- Source and destination ports
- Observed protocol
- Repeated sequences
- Inclusion of an IP inside a CIDR range (`ISSUBSET`)

## Examples

- `[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']`  
  Looks for traffic whose destination is a specific IPv4 address.

- `[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 5 TIMES WITHIN 1800 SECONDS`  
  Attempts to detect five repeated traffic events to `example.com` within 30 minutes.

- `[network-traffic:protocols = 'udp' AND network-traffic:dst_port = 53]`  
  Looks for UDP traffic to port 53, typically DNS.

- `[network-traffic:src_ref.value = '10.0.0.5' AND network-traffic:dst_ref.value = '203.0.113.10' AND network-traffic:dst_port = 443 AND network-traffic:protocols = 'tcp']`  
  Looks for a specific TCP communication from one source IP to one destination IP on port 443.

- `[network-traffic:src_port >= 1024 AND network-traffic:dst_port <= 1024]`  
  Looks for patterns where the source port is high and the destination port is low, useful for client-server or outbound connections to known services.

- `[network-traffic:src_ref.value ISSUBSET '10.0.0.0/8' AND network-traffic:protocols = 'tcp']`  
  Looks for TCP traffic whose source belongs to the private range `10.0.0.0/8`.

- `[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value ISSUBSET '203.0.113.0/24']`  
  Looks for traffic directed to an IP within that CIDR range.

- `[network-traffic:dst_ref.value LIKE '192.168.%']`  
  Looks for traffic whose destination appears to belong to a private `192.168.x.x` network.

- `[network-traffic:protocols = 'http']`  
  Looks for traffic tagged as HTTP.

---

# 4. Detection on standalone network observables

## What kinds of things it can detect

These patterns operate on network observables **without the full context of a connection**. They are useful for representing standalone indicators: an IP, a domain, a URL, or a MAC address.

## Observables and attributes involved

### Observables
- `ipv4-addr`
- `ipv6-addr`
- `domain-name`
- `url`
- `mac-addr`

### Attributes used
- `ipv4-addr:value`
- `ipv6-addr:value`
- `domain-name:value`
- `domain-name:resolves_to_refs[*].value`
- `url:value`
- `mac-addr:value`

### What information they try to select
- Exact IP
- CIDR range
- Exact domain or subdomain pattern
- Exact URL or path pattern
- Exact MAC address

---

## 4.1 IPv4

### Examples
- `[ipv4-addr:value = '8.8.8.8']`  
  Looks for a specific IP.

- `[ipv4-addr:value ISSUBSET '198.51.100.0/24']`  
  Attempts to detect IPs that belong to that CIDR block.

- `[ipv4-addr:value ISSUBSET '10.0.0.0/8']`  
  Attempts to detect IPs within the private range `10.0.0.0/8`.

- `[ipv4-addr:value = '198.51.100.0/24']`  
  Looks for that exact value, expressed as a CIDR block.

- `[ipv4-addr:value = '127.0.0.1']`  
  Looks for the loopback address.

## 4.2 IPv6

### Examples
- `[ipv6-addr:value ISSUBSET '2001:db8::/32']`  
  Attempts to detect IPv6 addresses within that prefix.

- `[ipv6-addr:value = '2001:db8::/96']`  
  Looks for that exact IPv6 block.

## 4.3 Domains

### Examples
- `[domain-name:value = 'evil.example']`  
  Looks for a specific domain.

- `[domain-name:value ISSUBSET 'evil.example']`  
  Attempts to express a subset relationship on a domain, although conceptually this semantic usually does not fit domains well.

- `[domain-name:value LIKE '%.example.com']`  
  Looks for subdomains of `example.com`.

- `[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']`  
  Attempts to relate a domain with an IP it would resolve to.

## 4.4 URLs

### Examples
- `[url:value = 'http://example.com/login']`  
  Looks for an exact URL.

- `[url:value != 'http://example.com/logout']`  
  Excludes a specific URL.

- `[url:value LIKE 'https://%/api/%']`  
  Looks for HTTPS URLs containing `/api/`.

- `[url:value MATCHES '^https://[^/]+/admin/.*$']`  
  Looks for HTTPS URLs whose path is under `/admin/`.

- `[url:value = 'http://example.com/foo' OR url:value = 'http://example.com/bar']`  
  Looks for one of two specific URLs.

- `[url:value ISSUBSET 'https://example.com/']`  
  Attempts to express a subset relationship on a URL, although semantically this is usually not the most appropriate operator for this observable type.

## 4.5 MAC

### Examples
- `[mac-addr:value = 'd2:fb:49:24:37:18']`  
  Looks for an exact MAC address.

- `[mac-addr:value ISSUBSET 'd2:fb:49:24:37:18']`  
  Attempts to use `ISSUBSET` on a MAC address, which generally does not make sense semantically as a subset operation.

---

# 5. Detection on user accounts (`user-account`)

## What kinds of things it can detect

Patterns on `user-account` are used to detect **specific accounts, account types, and combinations of identity-related attributes**.

## Observables and attributes involved

### Main observable
- `user-account`

### Attributes used
- `user-account:account_type`
- `user-account:user_id`
- `user-account:account_login`

### What information they try to select
- Account type
- Internal identifier
- Login name
- Specific sets of users

## Examples

- `[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter']`  
  Looks for a specific Unix account with a specific UID and login.

- `[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']`  
  Attempts to detect three specific accounts simultaneously within the same logical expression.

---

# 6. Detection on email messages (`email-message`)

## What kinds of things it can detect

Patterns on `email-message` are used to detect **specific emails based on sender, subject, or other message properties**.

## Observables and attributes involved

### Main observable
- `email-message`

### Attributes used
- `email-message:sender_ref.value`
- `email-message:subject`

### What information they try to select
- Exact sender
- Email topic or subject

## Examples

- `[email-message:sender_ref.value = 'jdoe@example.com' AND email-message:subject = 'Conference Info']`  
  Looks for emails sent by `jdoe@example.com` with the subject `Conference Info`.

---

# 7. Detection on directories (`directory`)

## What kinds of things it can detect

Patterns on `directory` are used to detect **sensitive directory paths, temporary directories, user folders, system paths, and time-based changes affecting directories**.

## Observables and attributes involved

### Main observable
- `directory`

### Attributes used
- `directory:path`
- `directory:mtime`

### What information they try to select
- Exact directory path
- Path matched by pattern
- Directories modified on or after a given date

## Examples

- `[directory:path = 'C:\\Windows\\System32']`  
  Looks for the exact directory `C:\Windows\System32`.

- `[directory:path LIKE 'C:\\Users\\%\\AppData\\Local\\Temp%']`  
  Looks for Windows user temporary directories.

- `[directory:path MATCHES '(?i)^/home/[^/]+/\\.ssh/?$']`  
  Looks for `.ssh` directories under Linux user home directories.

- `[directory:mtime >= t'2025-01-01T00:00:00Z' AND directory:path LIKE '/var/log/%']`  
  Looks for directories under `/var/log/` modified since that date.

- `[directory:path LIKE 'C:\\Windows\\Tasks%' AND directory:mtime > t'2025-01-01T00:00:00Z']`  
  Looks for directories under `C:\Windows\Tasks` modified after that date.

---

# 8. Detection on autonomous systems (`autonomous-system`)

## What kinds of things it can detect

Patterns on `autonomous-system` are used to select **specific ASNs, provider names, associated RIRs, or number ranges**. They are useful for characterizing network infrastructure.

## Observables and attributes involved

### Main observable
- `autonomous-system`

### Attributes used
- `autonomous-system:number`
- `autonomous-system:name`
- `autonomous-system:rir`

### What information they try to select
- ASN number
- Autonomous system name
- Associated regional registry (RIR)

## Examples

- `[autonomous-system:number = 13335]`  
  Looks for a specific ASN.

- `[autonomous-system:number > 64511]`  
  Looks for ASNs above that threshold.

- `[autonomous-system:name = 'Cloudflare, Inc.']`  
  Looks for an autonomous system by exact name.

- `[autonomous-system:name LIKE '%Google%']`  
  Looks for ASNs whose name contains `Google`.

- `[autonomous-system:rir = 'ARIN']`  
  Looks for ASNs associated with ARIN.

- `[autonomous-system:number > 64511 AND autonomous-system:rir = 'RIPE']`  
  Looks for high ASNs within the RIPE scope.

- `[autonomous-system:name MATCHES '^(?i)(cloudflare|google|microsoft).*$']`  
  Looks for ASNs whose name starts with Cloudflare, Google, or Microsoft, case-insensitively.

---

# 9. Detection on files (`file`)

## What kinds of things it can detect

Patterns on `file` are used to detect **suspicious file names, malicious extensions, unusual sizes, relevant timestamps, and known hashes**.

## Observables and attributes involved

### Main observable
- `file`

### Attributes used
- `file:name`
- `file:ctime`
- `file:atime`
- `file:mtime`
- `file:size`
- `file:hashes.'SHA-256'`
- `file:hashes.'SHA-1'`

### What information they try to select
- Exact name or name pattern
- File extension
- Creation, access, or modification time
- Size
- Known or excluded hash

## Examples

### Specific files
- `[file:name = 'cmd.exe']`  
  Looks for the file `cmd.exe`.

- `[file:name = 'invoice.pdf' AND file:size > 200000]`  
  Looks for an `invoice.pdf` of significant size.

- `[file:name = 'setup.exe']` together with an excluded hash  
  Looks for a `setup.exe` whose SHA-1 is not a specific expected one.

### Timestamps
- `[file:ctime = t'2024-10-01T08:30:00Z']`  
  Looks for files created at that exact timestamp.

- `[file:atime >= t'2025-01-01T00:00:00Z']`  
  Looks for files accessed on or after that date.

- `[file:mtime >= t'2025-01-01T00:00:00Z' AND file:mtime < t'2026-01-01T00:00:00Z']`  
  Looks for files modified within that time range.

- `[file:name != 'readme.txt' AND file:ctime < t'2023-01-01T00:00:00Z']`  
  Excludes `readme.txt` and looks for older files.

### Size
- `[file:size > 1048576]`  
  Looks for files larger than 1 MB.

- `[file:size <= 512000]`  
  Looks for small or medium-sized files.

- `[file:size >= 20000 AND file:size <= 40000 AND file:name LIKE '%.lnk']`  
  Looks for `.lnk` shortcuts within a specific size range.

- `[file:name LIKE '%backup%' AND file:ctime >= t'2025-02-01T00:00:00Z' AND file:size > 10485760]`  
  Looks for large backup-like files created recently.

### Name patterns
- `[file:name LIKE '%.exe']`  
  Looks for executables.

- `[file:name LIKE 'invoice_%']`  
  Looks for files whose name starts with `invoice_`.

- `[file:name LIKE '%.docm']`  
  Looks for Word documents with macros.

- `[file:name MATCHES '^invoice_[0-9]{4}\\.pdf$']`  
  Looks for PDFs following the `invoice_####.pdf` naming convention.

- `[file:name MATCHES '^(update|patch|hotfix).+\\.(exe|msi)$']`  
  Looks for executables or installers disguised as updates.

- `[file:name != 'svchost.exe' AND file:name MATCHES '^svchost\\.[a-z0-9]{2,4}\\.exe$']`  
  Looks for files imitating `svchost.exe` with suspicious suffixes.

- `[file:name LIKE '%.pdf.exe' AND file:size < 500000]`  
  Looks for double extensions, a common user deception technique.

- `[file:name MATCHES '^report.+\\.(exe|scr)$' AND file:ctime > t'2024-01-01T00:00:00Z']`  
  Looks for recently created `report*` files with executable extensions.

### Hashes
- `[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f' AND file:name LIKE '%.pdf']`  
  Looks for a file with a known hash that is also presented as a PDF.

- `[file:hashes.'SHA-1' != '3395856ce81f2b7382dee72602f798b642f14140' AND file:name = 'setup.exe']`  
  Looks for a `setup.exe` whose hash does not match the expected one, useful for integrity checks or tampering detection.

---

# 10. Practical summary for analysts and agents

The provided patterns are especially strong for:

- **Processes and command lines**
- **Windows registry**
- **Files**
- **Directory paths**
- **User identities**
- **Network activity with connection context (`network-traffic`)**
- **Standalone network indicators (IP, domains, URLs, MAC)**
- **Email messages**
- **Network infrastructure by ASN**

## What kinds of detection logic appear

The examples use several families of detection logic:

- **Exact equality**: `=`
- **Inequality**: `!=`
- **Numeric or temporal comparisons**: `>`, `>=`, `<`, `<=`
- **Simple patterns**: `LIKE`
- **Regular expressions**: `MATCHES`
- **CIDR ranges or network inclusion**: `ISSUBSET`
- **Condition combination**: `AND`, `OR`
- **Temporal sequences**: `FOLLOWEDBY`
- **Temporal frequency**: `REPEATS ... WITHIN ...`

## Conceptual recommendation

For an analyst or an AI agent, the best way to understand these patterns is to read them as:

- **Which observable they are looking at**
- **Which observable attribute they are filtering**
- **Which operator they are using**
- **Which operational behavior they want to represent**

For example:

- `process:command_line` usually expresses **execution behavior**
- `windows-registry-key:key` usually expresses **persistence or configuration**
- `network-traffic:*` usually expresses **communication**
- `file:name`, `file:size`, `file:hashes.*` usually express **artifacts**
- `user-account:*` usually expresses **identity**
- `directory:path` usually expresses **sensitive location**
- `autonomous-system:*` usually expresses **infrastructure context**

---
