# Threat Intelligence Sources

## Currently Implemented (5 feeds)

### 1. AlienVault OTX (Open Threat Exchange)
- **Type**: Community threat intelligence
- **API**: Free with API key
- **Data**: Pulses with IOCs (IPs, domains, URLs, hashes), MITRE techniques
- **URL**: https://otx.alienvault.com/
- **Status**: ✅ Implemented

### 2. Abuse.ch URLhaus
- **Type**: Malicious URL database
- **API**: Free, no key required
- **Data**: Recent malicious URLs, malware families
- **URL**: https://urlhaus.abuse.ch/
- **Status**: ✅ Implemented

### 3. Abuse.ch ThreatFox
- **Type**: IOC sharing platform
- **API**: Free, no key required
- **Data**: IPs, domains, URLs, hashes with malware context
- **URL**: https://threatfox.abuse.ch/
- **Status**: ✅ Implemented

### 4. CISA Known Exploited Vulnerabilities (KEV)
- **Type**: Government vulnerability catalog
- **API**: Free, no key required
- **Data**: CVEs actively exploited in the wild
- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Status**: ✅ Implemented

### 5. GreyNoise
- **Type**: Internet scanner intelligence
- **API**: Free tier with API key (10k queries/month)
- **Data**: Mass scanning IPs, benign vs malicious classification
- **URL**: https://www.greynoise.io/
- **Status**: ✅ Implemented

---

## New Integrations (Requested)

### 6. VirusTotal
- **Type**: File/URL reputation and malware analysis
- **API**: Free tier with API key (500 requests/day)
- **Data**:
  - File hashes with AV vendor detections
  - URL reputation scores
  - Domain/IP WHOIS and passive DNS
  - Malware family classifications
- **Rate Limits**: 4 requests/minute (free tier)
- **URL**: https://www.virustotal.com/
- **Implementation**: ✅ Planned

### 7. Hybrid Analysis
- **Type**: Malware sandbox analysis
- **API**: Free tier with API key (200 submissions/month)
- **Data**:
  - Sandbox execution reports
  - Network indicators (IPs, domains contacted)
  - File system modifications
  - MITRE ATT&CK technique mappings
- **URL**: https://www.hybrid-analysis.com/
- **Implementation**: ✅ Planned

### 8. Shodan
- **Type**: Internet-connected device search engine
- **API**: Paid API (minimum $59/month), but limited free tier with API key
- **Data**:
  - Exposed services and ports
  - IoT device information
  - Vulnerable software versions
  - SSL certificate data
- **Free Tier**: 100 queries/month
- **URL**: https://www.shodan.io/
- **Implementation**: ✅ Planned

### 9. MISP (Malware Information Sharing Platform)
- **Type**: Open-source threat intelligence platform
- **API**: Free (requires self-hosted or third-party instance)
- **Data**:
  - Community-shared IOCs
  - Event-based threat intelligence
  - Attribute galaxies and clusters
  - MITRE ATT&CK mappings
- **URL**: https://www.misp-project.org/
- **Implementation**: ✅ Planned (requires MISP instance URL)

### 10. OpenCTI
- **Type**: Open cyber threat intelligence platform
- **API**: Free (requires self-hosted or third-party instance)
- **Data**:
  - Structured threat intelligence (STIX 2.1)
  - Threat actors, intrusion sets, campaigns
  - Indicators with relationships
  - MITRE ATT&CK integration
- **URL**: https://www.opencti.io/
- **Implementation**: ✅ Planned (requires OpenCTI instance URL)

### 11. ThreatConnect (Optional)
- **Type**: Commercial threat intelligence platform
- **API**: Paid service (free tier limited)
- **Data**: Premium threat intelligence, IOCs, adversary profiles
- **URL**: https://threatconnect.com/
- **Implementation**: ⚠️ Optional (requires paid subscription)

### 12. Recorded Future (Optional)
- **Type**: Premium threat intelligence
- **API**: Paid service (enterprise pricing)
- **Data**: Predictive threat intelligence, risk scoring
- **URL**: https://www.recordedfuture.com/
- **Implementation**: ⚠️ Optional (requires paid subscription)

---

## Additional Free Sources

### 13. AbuseIPDB
- **Type**: IP address abuse database
- **API**: Free tier with API key (1,000 checks/day)
- **Data**:
  - IP reputation scores
  - Abuse reports and categories
  - ISP and geolocation
  - Confidence ratings
- **URL**: https://www.abuseipdb.com/
- **Implementation**: ✅ Planned

### 14. PhishTank
- **Type**: Phishing URL database
- **API**: Free with API key
- **Data**:
  - Verified phishing URLs
  - Submission timestamps
  - Target brands
- **URL**: https://www.phishtank.com/
- **Implementation**: ✅ Planned

### 15. Abuse.ch Feodo Tracker
- **Type**: Botnet C2 tracker
- **API**: Free, no key required
- **Data**:
  - Active C2 servers (IPs)
  - Malware families (Emotet, TrickBot, etc.)
  - Last seen timestamps
- **URL**: https://feodotracker.abuse.ch/
- **Implementation**: ✅ Planned

### 16. Abuse.ch SSL Blacklist
- **Type**: Malicious SSL certificate database
- **API**: Free, no key required
- **Data**:
  - SHA1 fingerprints of malicious SSL certs
  - Associated malware families
  - Destination IPs
- **URL**: https://sslbl.abuse.ch/
- **Implementation**: ✅ Planned

### 17. Abuse.ch Malware Bazaar
- **Type**: Malware sample repository
- **API**: Free, no key required
- **Data**:
  - Recent malware samples (hashes)
  - File signatures and tags
  - Malware families and campaigns
- **URL**: https://bazaar.abuse.ch/
- **Implementation**: ✅ Planned

### 18. URLScan.io
- **Type**: URL scanning and analysis service
- **API**: Free tier (1000 submissions/day, 10,000 searches/day)
- **Data**:
  - URL screenshots and DOM analysis
  - Network requests and IPs
  - Malicious verdict scores
  - Technology fingerprints
- **URL**: https://urlscan.io/
- **Implementation**: ✅ Planned

### 19. Pulsedive
- **Type**: Community threat intelligence platform
- **API**: Free tier with API key (30 requests/min)
- **Data**:
  - IOCs with risk scores
  - Threat feeds and properties
  - Historical data
- **URL**: https://pulsedive.com/
- **Implementation**: ✅ Planned

### 20. Blocklist.de
- **Type**: Brute force attack tracker
- **API**: Free (file downloads, no API key)
- **Data**:
  - SSH/RDP/FTP brute force IPs
  - Attack timestamps
  - Service-specific blocklists
- **URL**: https://www.blocklist.de/
- **Implementation**: ✅ Planned

### 21. Talos Intelligence
- **Type**: Cisco threat intelligence
- **API**: Limited free access
- **Data**:
  - IP/domain reputation
  - SNORT rules
  - Threat advisories
- **URL**: https://talosintelligence.com/
- **Implementation**: ⚠️ Evaluation needed

### 22. Spamhaus DROP/EDROP
- **Type**: Don't Route Or Peer lists
- **API**: Free (file downloads)
- **Data**:
  - Netblocks of spam/malware operations
  - Hijacked networks
- **URL**: https://www.spamhaus.org/drop/
- **Implementation**: ✅ Planned

### 23. Cybercrime Tracker
- **Type**: C2 panel tracker
- **API**: Free (HTML scraping or data exports)
- **Data**:
  - Active C2 panels
  - Malware families
  - Panel URLs and IPs
- **URL**: https://cybercrime-tracker.net/
- **Implementation**: ⚠️ No official API

### 24. MalwareBazaar
- **Type**: Malware sample sharing (Abuse.ch)
- **API**: Free
- **Data**: Recent malware hashes, tags, signatures
- **URL**: https://bazaar.abuse.ch/
- **Status**: Same as #17 (Abuse.ch Malware Bazaar)

---

## RSS/Blog Feeds for Threat Intelligence

### 25. CISA Alerts RSS
- **Type**: Government security alerts
- **URL**: https://www.cisa.gov/uscert/ncas/alerts.xml
- **Data**: Critical infrastructure alerts, IOCs, mitigation guidance

### 26. US-CERT Current Activity
- **Type**: Government security updates
- **URL**: https://www.cisa.gov/uscert/ncas/current-activity.xml
- **Data**: Recent cyber activity and alerts

### 27. Krebs on Security
- **Type**: Security news and investigation
- **URL**: https://krebsonsecurity.com/feed/
- **Data**: In-depth security journalism, breach reports

### 28. The Hacker News
- **Type**: Cybersecurity news
- **URL**: https://feeds.feedburner.com/TheHackersNews
- **Data**: Latest security news, vulnerabilities, tools

### 29. Bleeping Computer
- **Type**: Tech and security news
- **URL**: https://www.bleepingcomputer.com/feed/
- **Data**: Malware analysis, vulnerabilities, security tools

### 30. Threatpost
- **Type**: Security news
- **URL**: https://threatpost.com/feed/
- **Data**: Vulnerability analysis, threat reports

### 31. Dark Reading
- **Type**: Enterprise security news
- **URL**: https://www.darkreading.com/rss.xml
- **Data**: Security trends, analysis, commentary

### 32. SecurityWeek RSS
- **Type**: Security industry news
- **URL**: https://www.securityweek.com/feed/
- **Data**: Threat intelligence, industry news

### 33. SANS Internet Storm Center
- **Type**: Security diary and handlers
- **URL**: https://isc.sans.edu/rssfeed.xml
- **Data**: Daily security diaries, IOCs, port reports

### 34. Recorded Future Blog
- **Type**: Threat intelligence research
- **URL**: https://www.recordedfuture.com/feed
- **Data**: Threat analysis, research reports

---

## Feed Categories Summary

| Category | Free Feeds | Paid/Limited Feeds | RSS Feeds |
|----------|------------|-------------------|-----------|
| **IOC Databases** | OTX, ThreatFox, URLhaus, AbuseIPDB, PhishTank, Pulsedive | - | - |
| **Malware Analysis** | Hybrid Analysis (limited), Malware Bazaar | VirusTotal (limited) | - |
| **Network Intelligence** | GreyNoise (limited), Feodo Tracker, Blocklist.de | Shodan (limited) | - |
| **Vulnerability Intel** | CISA KEV, NVD | - | CISA Alerts |
| **Threat Platforms** | - | MISP (self-hosted), OpenCTI (self-hosted), ThreatConnect, Recorded Future | - |
| **News/Research** | - | - | 10 RSS feeds |

---

## API Key Requirements

| Feed | API Key Required | Free Tier Limits | Paid Options |
|------|------------------|------------------|--------------|
| AlienVault OTX | ✅ Yes | Unlimited (community) | N/A |
| URLhaus | ❌ No | Unlimited | N/A |
| ThreatFox | ❌ No | Unlimited | N/A |
| CISA KEV | ❌ No | Unlimited | N/A |
| GreyNoise | ✅ Yes | 10k queries/month | $500+/month |
| VirusTotal | ✅ Yes | 500 req/day, 4 req/min | $15+/month |
| Hybrid Analysis | ✅ Yes | 200 submissions/month | Custom pricing |
| Shodan | ✅ Yes | 100 queries/month | $59+/month |
| MISP | ⚠️ Instance-specific | Depends on instance | Self-hosted or cloud |
| OpenCTI | ⚠️ Instance-specific | Depends on instance | Self-hosted or cloud |
| AbuseIPDB | ✅ Yes | 1,000 checks/day | $20+/month |
| PhishTank | ✅ Yes | Unlimited | N/A |
| URLScan.io | ⚠️ Optional | 1k submissions/day | Free |
| Pulsedive | ✅ Yes | 30 req/min | $49+/month |
| Feodo Tracker | ❌ No | Unlimited | N/A |
| SSL Blacklist | ❌ No | Unlimited | N/A |
| Malware Bazaar | ❌ No | Unlimited | N/A |
| Blocklist.de | ❌ No | Unlimited | N/A |
| Spamhaus DROP | ❌ No | Unlimited | N/A |

---

## Integration Priority

### High Priority (Free, No Key Required)
1. ✅ Feodo Tracker (Abuse.ch)
2. ✅ SSL Blacklist (Abuse.ch)
3. ✅ Malware Bazaar (Abuse.ch)
4. ✅ Blocklist.de
5. ✅ Spamhaus DROP
6. ✅ RSS Feeds (CISA, SANS, etc.)

### Medium Priority (Free, API Key Required)
1. ✅ AbuseIPDB
2. ✅ PhishTank
3. ✅ Pulsedive
4. ✅ URLScan.io
5. ✅ VirusTotal (limited)

### Low Priority (Paid/Limited)
1. ⚠️ Hybrid Analysis (limited free tier)
2. ⚠️ Shodan (very limited free tier)
3. ⚠️ GreyNoise (already implemented, limited free)

### Instance-Based (Requires Setup)
1. 🔧 MISP (requires MISP server)
2. 🔧 OpenCTI (requires OpenCTI server)

### Optional (Paid Only)
1. 💰 ThreatConnect
2. 💰 Recorded Future

---

## Next Steps

1. Implement high-priority feeds (no API key required)
2. Implement medium-priority feeds (free API keys)
3. Add RSS feed parser for threat intelligence blogs
4. Implement cross-feed correlation and confidence scoring
5. Add automated enrichment pipeline
6. Document configuration for instance-based feeds (MISP, OpenCTI)
7. Create optional integrations for paid services
