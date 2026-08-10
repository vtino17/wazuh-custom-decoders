# Wazuh Custom Decoders

[![CI](https://img.shields.io/github/actions/workflow/status/vtino17/wazuh-custom-decoders/validate.yml?style=flat-square&label=CI)](https://github.com/vtino17/wazuh-custom-decoders/actions)

An initial Wazuh SIEM decoder and alert rules for MikroTik RouterOS syslog.

## Why this exists

Custom appliances need decoders and rules that match their emitted log format.
This repository starts with a small, reviewable MikroTik baseline.

## Contents

| Decoder | Source | Purpose | Alerts |
|---------|--------|---------|--------|
| MikroTik | RFC-style syslog | Firewall denies, login failures, logins, config changes | 4 |

The repository currently ships only the MikroTik files listed above. Other
integrations are roadmap items and must not be treated as available coverage.

## Quick Install

```bash
git clone https://github.com/vtino17/wazuh-custom-decoders.git
cd wazuh-custom-decoders

# Copy decoders
cp decoders/*.xml /var/ossec/etc/decoders/
# Copy rules
cp rules/*.xml /var/ossec/etc/rules/

# Restart Wazuh manager
systemctl restart wazuh-manager

# Verify
/var/ossec/bin/wazuh-logtest
```

## Decoder: MikroTik Firewall Drop

The decoder accepts RFC-style RouterOS syslog records such as:

```
<facility> <timestamp> <hostname> firewall,info forward: in:br-guest out:bridge-local ...
```

**Decoder** (`decoders/0020-mikrotik-decoder.xml`):

```xml
<decoder name="mikrotik">
  <prematch type="pcre2">^&lt;\d+&gt;</prematch>
  <regex type="pcre2">^&lt;(\d+)&gt;(\S+\s+\d+\s+\S+)\s+(\S+)\s+(.*)$</regex>
  <order>facility, timestamp, hostname, detail</order>
</decoder>
```

**Rules excerpt** (`rules/0020-mikrotik-rules.xml`):

```xml
<group name="mikrotik,">
  <rule id="100001" level="0">
    <decoded_as>mikrotik</decoded_as>
    <description>MikroTik generic event</description>
  </rule>

  <rule id="100002" level="7">
    <if_sid>100001</if_sid>
    <match>firewall,</match>
    <regex type="pcre2">(?i)\b(drop|denied)\b</regex>
    <description>MikroTik firewall denied traffic</description>
    <group>firewall,network,</group>
  </rule>

  <rule id="100003" level="10">
    <if_sid>100001</if_sid>
    <match>login failure</match>
    <description>MikroTik authentication failure</description>
    <group>authentication_failed,</group>
  </rule>
</group>
```

## Testing

```bash
# Test a MikroTik syslog entry
echo '<14>Jul 21 08:15:00 mikrotik-lan firewall,info forward: in:br-guest out:bridge-local, src-mac AA:BB:CC:DD:EE:FF, proto TCP 10.0.30.5:54321->192.168.1.1:443, len 60' | \
/var/ossec/bin/wazuh-logtest

```

## File Structure

```
wazuh-custom-decoders/
├── decoders/
│   └── 0020-mikrotik-decoder.xml
├── rules/
│   └── 0020-mikrotik-rules.xml
├── tests/
│   └── validate_rules.py
└── README.md
```

## Requirements

- Wazuh Manager 4.7+
- Python 3.8+ (only for the repository validation test)
- Syslog forwarding from MikroTik devices

---

**Built for the Wazuh community by [vtino17](https://github.com/vtino17).**
