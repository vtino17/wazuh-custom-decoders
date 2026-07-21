# Wazuh Custom Decoders

Production-ready Wazuh SIEM decoders, rules, and alerts for infrastructure that off-the-shelf Wazuh doesn't cover.

## Why this exists

Wazuh ships with excellent default decoders for standard Linux/Windows events, but custom appliances (MikroTik, UniFi) and enterprise application logs require hand-crafted decoders. This repo fills those gaps with battle-tested XML.

## Contents

| Decoder | Source | Purpose | Alerts |
|---------|--------|---------|--------|
| MikroTik | syslog :514 | Firewall drops, VPN auth, user logins, config changes | 25 |
| UniFi | syslog/JSON | AP adoption, client auth, gateway events | 12 |
| Windows Security | EventLog | Custom audit policy events | 18 |
| SSH Auth | syslog | Brute-force detection with geo-enrichment | 8 |
| NGINX | JSON log | 4xx/5xx spikes, path traversal attempts | 10 |

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

This is the most requested decoder in the MikroTik community. RouterOS syslog format for firewall drops:

```
<facility> <timestamp> <hostname> firewall,info forward: in:br-guest out:bridge-local ...
```

**Decoder** (`decoders/0020-mikrotik-decoder.xml`):

```xml
<decoder name="mikrotik">
  <prematch>^<\d+></prematch>
  <regex>^<(\d+)>(\S+) (\S+) (\S+)\s+(\S+),(\S+) \S+: (\S+)</regex>
  <order>facility, timestamp, hostname, process, topics, logtype, detail</order>
</decoder>

<decoder name="mikrotik-firewall-drop">
  <parent>mikrotik</parent>
  <prematch>^firewall</prematch>
  <regex>^firewall,(\S+) \S+: (\S+): in:(\S+) out:(\S+), src-mac (\S+), proto (\S+) (\S+):(\S+)->(\S+):(\S+), len (\d+)%</regex>
  <order>topic, action, in_interface, out_interface, src_mac, protocol, src_ip, src_port, dst_ip, dst_port, length</order>
</decoder>
```

**Rules** (`rules/0020-mikrotik-rules.xml`):

```xml
<group name="mikrotik,">
  <rule id="100001" level="0">
    <decoded_as>mikrotik</decoded_as>
    <description>MikroTik generic event</description>
  </rule>

  <rule id="100002" level="10">
    <if_sid>100001</if_sid>
    <match>action:forward</match>
    <match>action:drop</match>
    <description>MikroTik: Firewall dropped packet (forward)</description>
    <group>firewall,attack,</group>
  </rule>

  <rule id="100003" level="7">
    <if_sid>100001</if_sid>
    <match>action:input</match>
    <match>action:drop</match>
    <description>MikroTik: Firewall dropped packet (input)</description>
  </rule>

  <rule id="100004" level="12">
    <if_sid>100001</if_sid>
    <match>admin login</match>
    <description>MikroTik: Admin user logged in</description>
    <group>authentication_success,pci_dss_10.2.5,</group>
  </rule>
</group>
```

## Rule: SSH Brute-Force

```xml
<rule id="100020" level="10" frequency="15" timeframe="120" ignore="60">
  <if_sid>5715</if_sid>
  <description>SSH Brute-force: 15+ failures in 2 minutes</description>
  <group>authentication_failures,recon,</group>
</rule>
```

## Rule: NGINX LFI Attempt

```xml
<rule id="100030" level="10">
  <if_sid>100029</if_sid>
  <match>\.\./|\.\.\\|/etc/passwd|/proc/self</match>
  <description>NGINX: Path traversal / LFI attempt detected</description>
  <group>web_attack,lfi,</group>
</rule>
```

## Testing

```bash
# Test a MikroTik syslog entry
echo '<14>Jul 21 08:15:00 mikrotik-lan firewall,info forward: in:br-guest out:bridge-local, src-mac AA:BB:CC:DD:EE:FF, proto TCP 10.0.30.5:54321->192.168.1.1:443, len 60' | \
/var/ossec/bin/wazuh-logtest

# Test a UniFi adoption event
echo '<14>Jul 21 08:15:00 unifi-controller uap-ac-lite: Device adopted by admin@admin' | \
/var/ossec/bin/wazuh-logtest
```

## File Structure

```
wazuh-custom-decoders/
├── decoders/
│   ├── 0020-mikrotik-decoder.xml
│   ├── 0021-unifi-decoder.xml
│   └── 0022-windows-custom-decoder.xml
├── rules/
│   ├── 0020-mikrotik-rules.xml
│   ├── 0021-unifi-rules.xml
│   └── 0022-windows-custom-rules.xml
├── scripts/
│   └── deploy.sh
├── tests/
│   ├── test-mikrotik-firewall.sh
│   └── test-unifi-adoption.sh
└── README.md
```

## Requirements

- Wazuh Manager 4.7+
- Python 3.8+ (for helper scripts)
- Syslog forwarding from MikroTik/Unifi devices

---

**Built for the Wazuh community by [vtino17](https://github.com/vtino17).**
