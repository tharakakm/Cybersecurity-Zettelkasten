# Network Security & Monitoring

**ID:** 2
**Level:** 1
**Parent:** None (Root Level)
**Tags:** #level1 #network-security #module2

## Overview

Network Security & Monitoring encompasses the technologies, processes, and practices used to protect network infrastructure, detect malicious activity, and respond to security incidents. Understanding how data travels through networks and being able to analyze network traffic for suspicious patterns is fundamental to modern cybersecurity operations.

This module provides comprehensive coverage of network security principles, monitoring techniques, and practical analysis skills. Students will learn to understand network protocols at a deep level, capture and analyze traffic using industry-standard tools, identify attack patterns and anomalies, configure security devices, and implement network security monitoring (NSM) programs.

The content progresses from foundational networking concepts through advanced traffic analysis and incident detection. Emphasis is placed on hands-on skills that enable immediate application in Security Operations Centers (SOCs), incident response teams, and network security roles. Real-world packet captures and attack scenarios provide practical experience identifying actual threats.

## Key Concepts

### Network Communication Fundamentals

**OSI and TCP/IP Models**:
The OSI (Open Systems Interconnection) seven-layer model and the four-layer TCP/IP model provide frameworks for understanding network communications. Each layer has distinct security implications:

- **Layer 1 (Physical)**: Cable tapping, physical access to network infrastructure
- **Layer 2 (Data Link)**: MAC flooding, ARP spoofing, VLAN hopping, CAM table attacks
- **Layer 3 (Network)**: IP spoofing, routing attacks, ICMP attacks
- **Layer 4 (Transport)**: TCP SYN floods, UDP floods, port scanning
- **Layer 5-7 (Session/Presentation/Application)**: Protocol exploits, application attacks, malware C2

**Critical Network Protocols**:
- **TCP/IP**: Connection-oriented, reliable delivery with three-way handshake
- **UDP**: Connectionless, fast but unreliable, used for DNS, streaming, VoIP
- **ICMP**: Network diagnostics, error reporting, exploited for reconnaissance and tunneling
- **ARP**: Maps IP addresses to MAC addresses, vulnerable to spoofing attacks
- **DNS**: Name resolution, frequently abused for C2 communications and data exfiltration
- **HTTP/HTTPS**: Web traffic, most common application protocol, TLS encryption
- **SSH**: Secure remote access, sometimes used for tunneling and lateral movement
- **SMB/CIFS**: Windows file sharing, common target for ransomware propagation

### Network Security Architecture

**Defense in Depth Principles**:
Network security relies on multiple overlapping layers of defense:
1. **Perimeter Security**: Firewalls, border routers with ACLs, DDoS protection
2. **Network Segmentation**: VLANs, DMZs, internal firewalls, micro-segmentation
3. **Access Control**: NAC (Network Access Control), 802.1X authentication
4. **Monitoring and Detection**: IDS/IPS, network traffic analysis, anomaly detection
5. **Encryption**: VPNs, TLS/SSL, encrypted protocols for data in transit

**Network Segmentation Strategies**:
- **DMZ (Demilitarized Zone)**: Public-facing servers isolated from internal network
- **Internal Segmentation**: Separating user networks, servers, management, guest WiFi
- **Micro-segmentation**: Granular policies between individual workloads
- **Air Gapping**: Physical isolation for highest-security systems
- **VLAN Segmentation**: Logical network separation at Layer 2
- **Zero Trust**: Never trust, always verify - continuous authentication and authorization

**Firewall Technologies**:
- **Packet Filtering**: Stateless inspection of packet headers (legacy)
- **Stateful Inspection**: Tracks connection state, understands protocols
- **Next-Generation Firewalls (NGFW)**: Deep packet inspection, application awareness, IPS
- **Web Application Firewalls (WAF)**: HTTP/HTTPS-specific protection against web attacks
- **Unified Threat Management (UTM)**: Multiple security functions in single appliance

### Packet Analysis and Traffic Inspection

**Packet Capture Fundamentals**:
Network packets contain headers and payloads that reveal:
- **Source and Destination**: IP addresses and MAC addresses
- **Ports and Protocols**: Service identification and communication type
- **Flags and Options**: TCP flags indicate connection state and purpose
- **Payload Data**: Application-layer content (if unencrypted)
- **Timing Information**: Packet arrival times and delays

**Berkeley Packet Filter (BPF) Syntax**:
Powerful filtering language for capturing specific traffic:
```
host 192.168.1.100          # Traffic to/from specific host
port 80 or port 443         # HTTP and HTTPS traffic
tcp[tcpflags] & tcp-syn != 0  # TCP SYN packets
src net 10.0.0.0/8          # Traffic from 10.0.0.0/8 network
icmp[icmptype] == 8         # ICMP echo requests (pings)
```

**Protocol Analysis Techniques**:
- **Three-Way Handshake**: SYN, SYN-ACK, ACK sequence establishes TCP connections
- **Connection Termination**: FIN/ACK or RST packets close connections
- **HTTP Request/Response**: GET, POST requests and status codes
- **DNS Queries**: A, AAAA, MX, TXT records and responses
- **TLS Handshake**: ClientHello, ServerHello, certificate exchange, encryption negotiation

### Network Security Monitoring (NSM)

**NSM Philosophy**:
NSM focuses on collecting and analyzing network data to detect and respond to intrusions. Unlike prevention-focused approaches, NSM assumes breaches will occur and emphasizes detection and response capabilities.

**Core NSM Data Types**:
1. **Full Packet Capture**: Complete network traffic stored for forensic analysis
2. **Session Data**: Connection metadata without payload (NetFlow, IPFIX)
3. **Transaction Data**: Protocol-specific events (DNS queries, HTTP requests)
4. **Extracted Content**: Files, executables extracted from network traffic
5. **Alert Data**: IDS/IPS signatures matching suspicious activity
6. **Statistical Data**: Network baselines, traffic volume, protocol distribution

**Intrusion Detection Systems (IDS)**:
- **Signature-Based**: Matches known attack patterns (Snort, Suricata rules)
- **Anomaly-Based**: Detects deviations from normal behavior
- **Protocol Analysis**: Identifies protocol violations and anomalies
- **Network-Based IDS (NIDS)**: Monitors network segments
- **Host-Based IDS (HIDS)**: Monitors individual systems

**Intrusion Prevention Systems (IPS)**:
IPS extends IDS capabilities with active blocking:
- **Inline Deployment**: Traffic passes through IPS, can be blocked
- **Automated Response**: Drop packets, reset connections, block IPs
- **Performance Considerations**: Must process at line rate without delays
- **False Positive Risk**: Incorrect blocking disrupts legitimate services

### Attack Pattern Recognition

**Reconnaissance Indicators**:
- **Port Scans**: Sequential or randomized connection attempts to many ports
- **Ping Sweeps**: ICMP echo requests to multiple hosts discovering active systems
- **DNS Enumeration**: Zone transfer attempts, subdomain brute-forcing
- **Banner Grabbing**: Service version fingerprinting
- **Vulnerability Scanning**: Nmap NSE scripts, Nessus, OpenVAS traffic patterns

**Exploitation Indicators**:
- **Malformed Packets**: Invalid flags, oversized packets, fragmentation attacks
- **Exploit Payloads**: Shellcode, NOP sleds, return-oriented programming
- **Buffer Overflow Attempts**: Repeated attempts with long input strings
- **SQL Injection**: Single quotes, UNION statements, SQL keywords in URLs
- **Command Injection**: Shell metacharacters in parameters

**Post-Exploitation Indicators**:
- **Command and Control (C2)**: Beaconing, regular intervals, uncommon ports
- **Lateral Movement**: SMB connections, WMI, PsExec, RDP to multiple internal hosts
- **Data Staging**: Large internal file transfers, archive creation
- **Data Exfiltration**: Large outbound transfers, DNS tunneling, HTTPS uploads
- **Persistence Mechanisms**: Scheduled task creation, service installation

**Common Attack Patterns**:
- **ARP Spoofing**: False ARP responses intercepting traffic (man-in-the-middle)
- **DNS Tunneling**: Encoding data in DNS queries to bypass firewalls
- **ICMP Tunneling**: Using ping packets to transmit covert data
- **HTTP/HTTPS C2**: Malware communicating via web protocols to blend in
- **Pass-the-Hash**: NTLM authentication without passwords
- **Kerberos Attacks**: Golden tickets, silver tickets, Kerberoasting

## Practical Applications

### Security Operations Center (SOC) Workflows

**Tier 1 Analyst Tasks**:
- Monitor IDS/IPS alerts and network anomaly detections
- Perform initial triage of security events
- Execute basic packet capture analysis for investigation
- Escalate confirmed incidents to Tier 2
- Document findings in ticketing systems
- Maintain false positive tuning lists

**Network Forensics Investigations**:
1. **Capture Evidence**: Collect full packet captures around incident timeframe
2. **Timeline Construction**: Map attacker activities across time
3. **Communication Analysis**: Identify C2 servers, exfiltration destinations
4. **Artifact Extraction**: Retrieve files, executables, malware samples from traffic
5. **Indicator Development**: Create IOCs (IPs, domains, file hashes) for detection
6. **Report Generation**: Document findings with packet evidence

### Implementing Network Security Monitoring

**NSM Architecture Components**:
- **Sensors**: Deployed at network chokepoints (border, datacenter, critical segments)
- **Collection Infrastructure**: Centralized packet storage and session databases
- **Analysis Platform**: SIEM, network analytics tools for alert correlation
- **Analyst Workstations**: Wireshark, threat intelligence, investigation tools
- **Orchestration**: SOAR platforms for automated response workflows

**Strategic Sensor Placement**:
- **Perimeter**: Monitor inbound/outbound traffic at Internet border
- **Internal Segments**: Between VLANs, before critical servers
- **DMZ**: Traffic to/from public-facing systems
- **Data Centers**: East-west traffic between servers
- **Remote Sites**: VPN termination points, branch offices

**Traffic Analysis Workflows**:
```
1. Establish Baseline
   - Document normal traffic patterns, volume, protocols
   - Identify business-critical communications
   - Map internal topology and key systems

2. Monitor for Anomalies
   - Unusual protocols or ports
   - Abnormal traffic volumes or destinations
   - Communications during off-hours
   - Failed authentication patterns

3. Investigate Alerts
   - Collect full packets for suspicious events
   - Correlate with endpoint and log data
   - Research indicators using threat intelligence
   - Determine if incident or false positive

4. Respond and Remediate
   - Contain compromised systems
   - Block malicious IPs/domains at firewall
   - Update detection rules
   - Document lessons learned
```

### Firewall and IPS Configuration

**Firewall Rule Best Practices**:
- **Default Deny**: Block all traffic, explicitly allow only necessary
- **Least Privilege**: Permit minimum required ports and protocols
- **Source/Destination Specificity**: Avoid "any" rules where possible
- **Logging**: Enable logging for denied traffic and policy violations
- **Review and Cleanup**: Regularly audit and remove obsolete rules
- **Documentation**: Comment rules explaining business justification

**Example Firewall Ruleset** (conceptual):
```
# Rule 1: Allow established connections
allow tcp from any to any established

# Rule 2: Allow outbound HTTPS from internal network
allow tcp from 10.0.0.0/8 to any port 443

# Rule 3: Allow inbound HTTPS to web servers in DMZ
allow tcp from any to 192.168.100.0/24 port 443

# Rule 4: Allow DNS to authorized servers
allow udp from 10.0.0.0/8 to 8.8.8.8,8.8.4.4 port 53

# Rule 5: Block known malicious IPs (threat intel feed)
deny ip from <threat_list> to any

# Rule 6: Default deny with logging
deny log ip from any to any
```

**IPS Tuning Methodology**:
1. **Initial Deployment in IDS Mode**: Monitor without blocking to baseline
2. **False Positive Analysis**: Identify signatures triggering on legitimate traffic
3. **Rule Customization**: Adjust thresholds, add exclusions for false positives
4. **Gradual IPS Enablement**: Block high-confidence signatures first
5. **Continuous Tuning**: Respond to new applications and changing environment

### Incident Response Using Network Data

**Malware C2 Detection**:
- Analyze beaconing patterns (regular intervals indicating automated check-ins)
- Identify unusual DNS queries (DGA domains, TXT record queries)
- Detect long connections to external IPs (persistent C2 channels)
- Correlate with threat intelligence feeds for known C2 infrastructure

**Data Exfiltration Investigation**:
- Identify large outbound transfers, especially during off-hours
- Detect DNS tunneling (oversized queries, unusual record types)
- Monitor HTTP/HTTPS uploads to cloud storage or paste sites
- Analyze FTP, SCP, or other file transfer protocols

**Lateral Movement Detection**:
- SMB connections between workstations (unusual peer-to-peer)
- RDP sessions originating from non-admin workstations
- WMI and PowerShell remoting across multiple systems
- Privilege escalation attempts and service account usage

## Security Implications

### Network Architecture Vulnerabilities

**Flat Network Risks**:
- Attackers with initial access can pivot freely to any system
- Malware spreads rapidly without segmentation barriers
- Single breach can compromise entire infrastructure
- Difficult to isolate incidents and limit damage
- No defense in depth - perimeter breach equals full compromise

**Segmentation Benefits and Challenges**:
- Contains breaches to isolated network zones
- Requires careful planning and ongoing maintenance
- Misconfiguration can create security gaps
- Legacy systems may not support modern segmentation
- Performance impact from inter-segment inspection

### Encrypted Traffic Challenges

**TLS/SSL Encryption Impact**:
- Hides malicious payloads from inspection tools
- Prevents signature-based detection of malware C2
- Limits DLP ability to detect data exfiltration
- Certificate pinning complicates decryption approaches
- TLS 1.3 reduces visibility into session establishment

**TLS Inspection Tradeoffs**:
**Benefits**:
- Enables deep packet inspection of encrypted traffic
- Allows malware detection in HTTPS communications
- Supports DLP policies for encrypted channels
- Detects exploitation attempts in encrypted payloads

**Risks and Concerns**:
- Privacy implications of decrypting user traffic
- Certificate trust violations and user warnings
- Performance overhead of decryption/re-encryption
- Decryption key compromise exposes all traffic
- Breaks certificate pinning for legitimate apps
- May violate compliance requirements (HIPAA, financial data)

**Alternatives to TLS Inspection**:
- DNS monitoring to detect malicious domains
- TLS fingerprinting and JA3 signatures
- Certificate analysis for suspicious issuers
- Connection metadata analysis (timing, volume)
- Endpoint-based detection and response

### Monitoring Blind Spots

**Common Visibility Gaps**:
- **East-West Traffic**: Internal system communications often unmonitored
- **Encrypted Protocols**: SSH, VPN, TLS 1.3 hide content
- **Cloud Services**: Traffic to SaaS applications outside network perimeter
- **Mobile Devices**: Cellular connections bypass network monitoring
- **IPv6 Networks**: Less mature monitoring tools and expertise
- **Out-of-Band Channels**: Physical access, USB, air-gapped systems

**Detection Evasion Techniques**:
- **Protocol Tunneling**: HTTP over DNS, ICMP tunneling
- **Encrypted C2**: HTTPS, DNS-over-HTTPS obfuscating communications
- **Low and Slow**: Stealthy data exfiltration avoiding volume triggers
- **Living off the Land**: Using legitimate tools (PowerShell, WMI)
- **Domain Fronting**: Disguising C2 traffic as major cloud services
- **Fast Flux**: Rapidly changing C2 infrastructure

### Operational Challenges

**Performance vs. Security**:
- Deep packet inspection adds latency
- Full packet capture requires significant storage
- IPS inline deployment can bottleneck throughput
- False positives disrupt legitimate business operations
- Monitoring infrastructure requires dedicated resources

**Alert Fatigue and Tuning**:
- High-volume alerting overwhelms analysts
- False positives reduce analyst effectiveness
- Requires continuous tuning as environment changes
- Balance between detection coverage and noise
- Risk of true positives being missed in alert flood

**Skill Requirements**:
- Network protocol expertise increasingly rare
- Packet analysis requires significant training
- Tool proliferation creates learning curve
- Analyst burnout from repetitive triage
- Difficulty hiring and retaining qualified analysts

### Compliance and Legal Considerations

**Regulatory Requirements**:
- **PCI-DSS**: Network segmentation, logging, IDS for cardholder data
- **HIPAA**: Encryption, access controls, audit trails for PHI
- **GDPR**: Data protection and breach notification requirements
- **SOX**: Financial system access controls and monitoring

**Legal Concerns**:
- Employee privacy expectations for network monitoring
- Data retention policies and litigation hold requirements
- Cross-border data transfer restrictions
- Lawful intercept and government access demands
- Admissibility of packet captures as evidence

## Tools & Techniques

### Packet Capture and Analysis

**Wireshark**:
- Industry-standard GUI packet analyzer for Windows, Mac, Linux
- Deep protocol inspection for 2000+ protocols
- Display filters for isolating specific traffic patterns
- Expert analysis detecting common problems
- File export capabilities (CSV, JSON, plain text)
- TLS decryption with private keys
- Real-time capture and offline analysis

**tcpdump**:
- Command-line packet capture for Unix/Linux systems
- Lightweight, minimal resource usage
- BPF filter syntax for precise capture
- Essential for remote/headless systems
- Integrates into automated scripts and pipelines
- Output formats compatible with Wireshark

**tshark**:
- Command-line version of Wireshark
- Automated packet analysis and statistics generation
- Suitable for server deployments without GUI
- Powerful for batch processing and reporting

### Network Scanning and Enumeration

**Nmap**:
- Port scanning and service discovery
- OS fingerprinting and version detection
- NSE (Nmap Scripting Engine) for vulnerability scanning
- Multiple scan techniques (SYN, connect, UDP, stealth)
- Timing options to avoid IDS detection
- Output formats: XML, normal, grepable

**Masscan**:
- High-speed Internet-scale port scanner
- Asynchronous transmission for massive parallelism
- Can scan entire IPv4 space in under 6 minutes
- Useful for attack surface mapping

### Intrusion Detection and Prevention

**Snort**:
- Open-source IDS/IPS with large rule community
- Signature-based detection with flexible rule language
- Packet logging and real-time alerting
- Three modes: sniffer, packet logger, NIDS
- Preprocessors for protocol analysis and normalization
- Extensive community rule sets and commercial rule options

**Suricata**:
- Modern multi-threaded IDS/IPS
- Hardware acceleration and GPU support
- Protocol detection independent of port
- File extraction and MD5 hashing
- Lua scripting for custom detection
- Compatible with Snort rules
- HTTP, TLS, DNS logging capabilities

**Zeek (formerly Bro)**:
- Network analysis framework and IDS
- Converts packets into high-level events and logs
- Scripting language for custom detection logic
- Protocol analysis and anomaly detection
- Generates structured logs (conn.log, dns.log, http.log)
- Excellent for network forensics and threat hunting

### Network Security Monitoring Platforms

**Security Onion**:
- Free Linux distribution for NSM
- Integrates Suricata, Zeek, Wazuh, Elasticsearch, Kibana
- Full packet capture with Stenographer
- Centralized management and analyst tools
- Ideal for lab and small production deployments

**NetworkMiner**:
- Passive network forensic analysis tool
- OS fingerprinting and session reconstruction
- File extraction from packet captures
- Credential harvesting and host profiling
- Windows-based with GUI interface

**Moloch (Arkime)**:
- Large-scale, indexed packet capture and search
- Web interface for searching and browsing
- Stores both packets and session metadata
- Integrates with Suricata, Zeek, threat intel
- Tagging and collaboration features

### Flow Analysis

**NetFlow/IPFIX Collectors**:
- **nfdump/nfcapd**: Command-line NetFlow collection and analysis
- **Silk (SiLK)**: Suite of network traffic analysis tools from CERT
- **ElastiFlow**: ElasticStack-based NetFlow visualization
- **Flowmon**: Commercial network monitoring and forensics

**Session Analysis**:
- Flow data provides metadata without payload
- Identifies communication patterns and volumes
- Detects anomalies (beaconing, large transfers)
- Lower storage requirements than full packet capture
- Limited detail for deep investigation

### Firewall and Network Device Tools

**pfSense/OPNsense**:
- Open-source firewall distributions (FreeBSD-based)
- Web GUI for rule management
- IDS/IPS integration (Snort, Suricata)
- VPN support (OpenVPN, IPsec, WireGuard)
- Traffic shaping and packet capture

**iptables/nftables**:
- Linux kernel firewall implementation
- Command-line rule configuration
- NAT, packet filtering, mangling
- nftables is modern replacement with improved syntax

**pfctl**:
- OpenBSD packet filter control
- Stateful firewall with sophisticated filtering
- Traffic normalization and QoS

### Protocol-Specific Tools

**DNS Analysis**:
- **dnstop**: Real-time DNS query monitoring
- **passivedns**: Passive DNS collection for forensics
- **dns**cap**: DNS traffic analysis and visualization

**HTTP/HTTPS Analysis**:
- **mitmproxy**: Interactive HTTPS proxy for inspection
- **Burp Suite**: Web application security testing proxy
- **curl/wget**: Command-line HTTP clients for testing

**SMB/CIFS Analysis**:
- **smbclient**: SMB client for testing and enumeration
- **enum4linux**: SMB enumeration tool
- **Responder**: LLMNR/NBT-NS poisoner and analyzer

### Automation and Scripting

**Python Libraries**:
- **Scapy**: Packet manipulation and creation
- **dpkt**: Fast packet parsing library
- **PyShark**: Python wrapper for tshark
- **Impacket**: Network protocol implementations

**Traffic Generation**:
- **hping3**: Packet crafting and testing
- **packETH**: Ethernet packet generator (GUI)
- **tcpreplay**: Replay packet captures for testing

### Threat Intelligence Integration

**Threat Intel Platforms**:
- **MISP**: Malware Information Sharing Platform
- **OpenCTI**: Open Cyber Threat Intelligence platform
- **AlienVault OTX**: Community threat intelligence

**IOC Checking**:
- **VirusTotal**: File and URL analysis
- **URLscan.io**: Website scanning and screenshot
- **IPVoid/AbuseIPDB**: IP reputation checking
- **Shodan**: Internet device search engine


## Related Topics

- [↓ OSI and TCP/IP models: Understanding network communication layers](2.1-OSI-and-TCPIP-models-Understanding-network-communication-layers.md)
- [↓ Common network protocols: HTTP/HTTPS, DNS, FTP, SSH, Telnet](2.2-Common-network-protocols-HTTPHTTPS-DNS-FTP-SSH-Telnet.md)
- [↓ Network devices and security: Routers, switches, firewalls, IDS/IPS](2.3-Network-devices-and-security-Routers-switches-firewalls-IDSIPS.md)
- [↓ Introduction to packet analysis with Wireshark](2.4-Introduction-to-packet-analysis-with-Wireshark.md)
- [↓ Capturing and filtering network traffic (BPF filters)](2.5-Capturing-and-filtering-network-traffic-BPF-filters.md)
- [↓ Identifying suspicious patterns: Port scans, ARP spoofing, DNS tunneling](2.6-Identifying-suspicious-patterns-Port-scans-ARP-spoofing-DNS-tunneling.md)
- [↓ Using tcpdump for command-line packet capture](2.7-Using-tcpdump-for-command-line-packet-capture.md)
- [↓ Network security monitoring (NSM) concepts and tools](2.8-Network-security-monitoring-NSM-concepts-and-tools.md)
- [↓ Firewall rule configuration and testing](2.9-Firewall-rule-configuration-and-testing.md)
- [↓ Lab: Analyze a simulated network attack using packet captures](2.10-Lab-Analyze-a-simulated-network-attack-using-packet-captures.md)

## References & Further Reading

### Books
- **"The Practice of Network Security Monitoring"** by Richard Bejtlich - Definitive NSM guide
- **"Applied Network Security Monitoring"** by Chris Sanders & Jason Smith
- **"Practical Packet Analysis"** by Chris Sanders - Wireshark fundamentals
- **"Network Forensics"** by Sherri Davidoff & Jonathan Ham

### Online Resources
- **Wireshark Documentation**: https://www.wireshark.org/docs/
- **tcpdump Manual**: https://www.tcpdump.org/manpages/tcpdump.1.html
- **Snort Documentation**: https://www.snort.org/documents
- **Suricata User Guide**: https://suricata.readthedocs.io/
- **Zeek Documentation**: https://docs.zeek.org/
- **Security Onion**: https://securityonionsolutions.com/
- **SANS Network Security Resources**: https://www.sans.org/network-security/

### Training and Certifications
- **SANS SEC503**: Intrusion Detection In-Depth
- **SANS SEC504**: Hacker Tools, Techniques, Exploits, and Incident Handling
- **SANS SEC511**: Continuous Monitoring and Security Operations
- **Wireshark Certified Network Analyst (WCNA)**
- **CompTIA CySA+**: Cybersecurity Analyst certification

### Community Resources
- **PacketLife.net**: Network cheat sheets and packet captures
- **Malware-Traffic-Analysis.net**: Real-world malware PCAP exercises
- **Chris Sanders Blog**: Applied NSM and packet analysis
- **r/netsec**: Network security subreddit
- **BPF Syntax Guide**: https://biot.com/capstats/bpf.html

### Standards and Frameworks
- **NIST SP 800-94**: Guide to Intrusion Detection and Prevention Systems
- **NIST SP 800-41**: Guidelines on Firewalls and Firewall Policy
- **NSA/CSS Technical Cyber Threat Framework**: https://www.nsa.gov/
- **MITRE ATT&CK**: Network-based detection techniques

---

*Note: This is part of a comprehensive Zettelkasten knowledge base for cybersecurity education. Links connect to related concepts for deeper exploration.*
