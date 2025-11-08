# Threat Intelligence Integration Guide

## Overview

DetectiveSloth now integrates with 20+ threat intelligence feeds, providing comprehensive coverage across:
- **File/URL Reputation**: VirusTotal, URLScan.io, Hybrid Analysis
- **IP Reputation**: AbuseIPDB, GreyNoise, Blocklist.de, Spamhaus DROP
- **Malware Intelligence**: Malware Bazaar, ThreatFox, Feodo Tracker, SSL Blacklist
- **Phishing**: PhishTank, URLhaus
- **Community Intelligence**: AlienVault OTX, Pulsedive
- **Exposed Services**: Shodan
- **Vulnerability Intelligence**: CISA KEV
- **Threat Platforms**: MISP, OpenCTI
- **RSS/Blog Feeds**: CISA Alerts, SANS ISC, Security Blogs

---

## Quick Start

### 1. Free Feeds (No Configuration Required)

These feeds work out of the box without any API keys:

```bash
# Update all free feeds
curl -X POST http://localhost:8000/api/threat-intel/update/urlhaus
curl -X POST http://localhost:8000/api/threat-intel/update/threatfox
curl -X POST http://localhost:8000/api/threat-intel/update/malware-bazaar
curl -X POST http://localhost:8000/api/threat-intel/update/feodo-tracker
curl -X POST http://localhost:8000/api/threat-intel/update/sslbl
curl -X POST http://localhost:8000/api/threat-intel/update/blocklist-de
curl -X POST http://localhost:8000/api/threat-intel/update/spamhaus-drop
curl -X POST http://localhost:8000/api/threat-intel/update/cisa-kev
curl -X POST http://localhost:8000/api/threat-intel/update/rss-feeds
```

### 2. Configure API Keys

Copy the example environment file:
```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and add your API keys (see configuration section below).

### 3. Update All Feeds

```bash
# Update all configured feeds
curl -X POST http://localhost:8000/api/threat-intel/update

# Include optional paid feeds
curl -X POST "http://localhost:8000/api/threat-intel/update?include_optional=true"
```

---

## Feed Configuration

### AlienVault OTX (Recommended)
**Type**: Free community threat intelligence
**API Limit**: Unlimited
**Registration**: https://otx.alienvault.com/api

```bash
# Get API key from OTX website
OTX_API_KEY=your_key_here
```

**Features**:
- Community-shared IOCs (IPs, domains, URLs, hashes)
- MITRE ATT&CK technique mappings
- Threat actor attribution
- Campaign tracking

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/otx?days=7"
```

---

### VirusTotal
**Type**: File/URL reputation
**API Limit**: 500 requests/day (free tier)
**Registration**: https://www.virustotal.com/gui/my-apikey

```bash
VIRUSTOTAL_API_KEY=your_key_here
```

**Features**:
- Multi-AV scan results
- Detection rates
- Malware family classification
- Reputation scores

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/virustotal?limit=100"
```

---

### Hybrid Analysis
**Type**: Malware sandbox analysis
**API Limit**: 200 submissions/month (free)
**Registration**: https://www.hybrid-analysis.com/apikeys/info

```bash
HYBRID_ANALYSIS_API_KEY=your_key_here
```

**Features**:
- Sandbox execution reports
- Network indicators (domains, IPs contacted)
- MITRE ATT&CK technique mappings
- Behavioral analysis

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/hybrid-analysis?days=7"
```

---

### Shodan
**Type**: Internet-connected device search
**API Limit**: 100 queries/month (free)
**Registration**: https://account.shodan.io/

```bash
SHODAN_API_KEY=your_key_here
```

**Features**:
- Exposed services and ports
- Vulnerability scanning
- IoT device information
- SSL certificate data

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/shodan?query=has_vuln:true&limit=100"
```

**Custom Queries**:
```bash
# Search for specific CVEs
curl -X POST "http://localhost:8000/api/threat-intel/update/shodan?query=vuln:CVE-2024-1234"

# Search for specific products
curl -X POST "http://localhost:8000/api/threat-intel/update/shodan?query=product:apache"
```

---

### AbuseIPDB
**Type**: IP abuse database
**API Limit**: 1,000 checks/day (free)
**Registration**: https://www.abuseipdb.com/account/api

```bash
ABUSEIPDB_API_KEY=your_key_here
```

**Features**:
- IP reputation scores
- Abuse reports and categories
- ISP and geolocation
- Confidence ratings

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/abuseipdb?confidence_min=75"
```

---

### GreyNoise
**Type**: Internet scanner intelligence
**API Limit**: 10,000 queries/month (free)
**Registration**: https://www.greynoise.io/

```bash
GREYNOISE_API_KEY=your_key_here
```

**Features**:
- Mass scanning IP classification
- Benign vs. malicious scanner detection
- Actor attribution
- Tag-based categorization

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/greynoise?classification=malicious"
```

---

### PhishTank
**Type**: Phishing URL database
**API Limit**: Unlimited (with key)
**Registration**: https://www.phishtank.com/api_info.php

```bash
PHISHTANK_API_KEY=your_key_here
```

**Features**:
- Verified phishing URLs
- Target brand identification
- Community-validated submissions

**API Endpoint**:
```bash
curl -X POST http://localhost:8000/api/threat-intel/update/phishtank
```

---

### URLScan.io
**Type**: URL scanning service
**API Limit**: 1,000 submissions/day, 10,000 searches/day (free)
**Registration**: https://urlscan.io/user/profile/

```bash
URLSCAN_API_KEY=your_key_here  # Optional, increases rate limits
```

**Features**:
- URL screenshots and DOM analysis
- Network requests
- Malicious verdict scores
- Technology fingerprinting

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/urlscan?limit=100"
```

---

### Pulsedive
**Type**: Community threat intelligence
**API Limit**: 30 requests/minute (free)
**Registration**: https://pulsedive.com/account/

```bash
PULSEDIVE_API_KEY=your_key_here
```

**Features**:
- IOCs with risk scores
- Threat feed aggregation
- Historical data
- Property-based filtering

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/pulsedive?risk=high"
```

---

### MISP (Malware Information Sharing Platform)
**Type**: Threat intelligence platform
**Requirement**: Self-hosted or third-party instance
**Documentation**: https://www.misp-project.org/

```bash
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your_key_here
```

**Features**:
- Event-based threat intelligence
- Community-shared IOCs
- MITRE ATT&CK integration
- Attribute galaxies and clusters

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/misp?days=7"

# Or with custom instance
curl -X POST http://localhost:8000/api/threat-intel/update/misp \
  -H "Content-Type: application/json" \
  -d '{"instance_url": "https://your-misp.com", "api_key": "your_key", "days": 7}'
```

---

### OpenCTI (Open Cyber Threat Intelligence)
**Type**: Threat intelligence platform
**Requirement**: Self-hosted or third-party instance
**Documentation**: https://www.opencti.io/

```bash
OPENCTI_URL=https://your-opencti-instance.com
OPENCTI_API_KEY=your_key_here
```

**Features**:
- STIX 2.1 structured intelligence
- Threat actors and intrusion sets
- Campaign tracking
- Knowledge graph relationships

**API Endpoint**:
```bash
curl -X POST "http://localhost:8000/api/threat-intel/update/opencti?limit=100"
```

---

### Free Feeds (No Configuration)

#### Abuse.ch URLhaus
Malicious URLs associated with malware distribution.

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/urlhaus
```

#### Abuse.ch ThreatFox
Community-shared IOCs (hashes, IPs, domains, URLs).

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/threatfox
```

#### Abuse.ch Malware Bazaar
Recent malware samples with signatures and tags.

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/malware-bazaar
```

#### Abuse.ch Feodo Tracker
Botnet C2 servers (Emotet, TrickBot, etc.).

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/feodo-tracker
```

#### Abuse.ch SSL Blacklist
Malicious SSL certificate fingerprints.

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/sslbl
```

#### CISA Known Exploited Vulnerabilities (KEV)
CVEs actively exploited in the wild.

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/cisa-kev
```

#### Blocklist.de
Brute force attack IPs (SSH, RDP, FTP, mail).

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/blocklist-de
```

#### Spamhaus DROP/EDROP
Hijacked netblocks and spam operations.

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/spamhaus-drop
```

#### RSS Feeds
Threat intelligence from security blogs and alerts.

Default feeds:
- CISA Alerts
- CISA Current Activity
- SANS ISC
- Bleeping Computer
- Krebs on Security
- Threatpost

```bash
curl -X POST http://localhost:8000/api/threat-intel/update/rss-feeds

# Or with custom feeds
curl -X POST http://localhost:8000/api/threat-intel/update/rss-feeds \
  -H "Content-Type: application/json" \
  -d '{"feeds": ["https://example.com/feed.xml"]}'
```

---

## API Endpoints Reference

### Feed Update Endpoints

| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/api/threat-intel/update` | POST | `include_optional` (bool) | Update all configured feeds |
| `/api/threat-intel/update/otx` | POST | `days` (int, default: 7) | AlienVault OTX pulses |
| `/api/threat-intel/update/virustotal` | POST | `limit` (int, default: 100) | VirusTotal IOCs |
| `/api/threat-intel/update/hybrid-analysis` | POST | `days` (int, default: 7) | Hybrid Analysis reports |
| `/api/threat-intel/update/shodan` | POST | `query` (str), `limit` (int) | Shodan search results |
| `/api/threat-intel/update/abuseipdb` | POST | `confidence_min` (int, default: 75) | AbuseIPDB blacklist |
| `/api/threat-intel/update/greynoise` | POST | `classification` (str, default: "malicious") | GreyNoise IPs |
| `/api/threat-intel/update/phishtank` | POST | - | PhishTank phishing URLs |
| `/api/threat-intel/update/urlscan` | POST | `limit` (int, default: 100) | URLScan.io results |
| `/api/threat-intel/update/pulsedive` | POST | `risk` (str, default: "high") | Pulsedive IOCs |
| `/api/threat-intel/update/misp` | POST | `days` (int, default: 7) | MISP events |
| `/api/threat-intel/update/opencti` | POST | `limit` (int, default: 100) | OpenCTI indicators |
| `/api/threat-intel/update/urlhaus` | POST | - | URLhaus malicious URLs |
| `/api/threat-intel/update/threatfox` | POST | - | ThreatFox IOCs |
| `/api/threat-intel/update/malware-bazaar` | POST | - | Malware Bazaar samples |
| `/api/threat-intel/update/feodo-tracker` | POST | - | Feodo Tracker C2s |
| `/api/threat-intel/update/sslbl` | POST | - | SSL Blacklist certs |
| `/api/threat-intel/update/blocklist-de` | POST | - | Blocklist.de IPs |
| `/api/threat-intel/update/spamhaus-drop` | POST | - | Spamhaus netblocks |
| `/api/threat-intel/update/cisa-kev` | POST | - | CISA KEV catalog |
| `/api/threat-intel/update/rss-feeds` | POST | `feeds` (list, optional) | RSS feed items |

### IOC Query Endpoints

| Endpoint | Method | Parameters | Description |
|----------|--------|------------|-------------|
| `/api/threat-intel/recent` | GET | `days`, `ioc_type`, `source`, `skip`, `limit` | Get recent IOCs |
| `/api/threat-intel/by-technique/{technique_id}` | GET | `skip`, `limit` | IOCs by MITRE technique |

---

## Automation & Scheduling

### Using Celery (Recommended)

The project includes Celery for automated feed updates. Configure in your environment:

```python
# backend/app/tasks/threat_intel.py
from celery import shared_task
from ..services.threat_intel_service import ThreatIntelService
from ..core.database import SessionLocal

@shared_task
def update_all_threat_intel():
    """Scheduled task to update all threat intelligence feeds."""
    db = SessionLocal()
    try:
        service = ThreatIntelService(db)
        results = await service.update_all_feeds()
        return results
    finally:
        db.close()
```

Schedule with Celery Beat:
```python
# backend/app/core/celery_config.py
from celery.schedules import crontab

beat_schedule = {
    'update-threat-intel': {
        'task': 'app.tasks.threat_intel.update_all_threat_intel',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours
    },
}
```

### Using Cron

```bash
# Add to crontab
0 */6 * * * curl -X POST http://localhost:8000/api/threat-intel/update
```

---

## Best Practices

### 1. Start Small
Begin with free feeds, then gradually add API-based feeds:
1. Free Abuse.ch feeds
2. AlienVault OTX
3. AbuseIPDB
4. VirusTotal (if needed)

### 2. Respect Rate Limits
- Monitor API usage via logs
- Use `limit` parameters appropriately
- Implement exponential backoff for failures

### 3. Feed Update Frequency

Recommended update intervals:
- **High-frequency** (every hour): CISA KEV, RSS feeds
- **Medium-frequency** (every 6 hours): OTX, ThreatFox, URLhaus
- **Low-frequency** (daily): VirusTotal, Shodan, Malware Bazaar

### 4. Storage Considerations
- Database size grows with feed volume
- Implement retention policies for old IOCs
- Use database indexing for performance

### 5. Confidence Scoring
IOCs from multiple sources have higher confidence:
- Cross-feed validation increases trust
- Source credibility weighting applied
- Recency affects scoring

---

## Troubleshooting

### API Key Issues
```bash
# Check if API key is configured
grep OTX_API_KEY backend/.env

# Test feed manually
curl -X POST http://localhost:8000/api/threat-intel/update/otx
```

### Rate Limiting
```json
{
  "success": false,
  "error": "Rate limit exceeded"
}
```
**Solution**: Reduce update frequency or upgrade API tier.

### Empty Results
```json
{
  "success": true,
  "message": "Successfully ingested 0 IOCs from OTX",
  "count": 0
}
```
**Possible causes**:
- Invalid API key
- No new data in timeframe
- Network connectivity issues

Check logs: `tail -f backend/logs/threat_intel.log`

---

## Next Steps

1. **Configure Enrichment**: IOCs are automatically enriched with context from multiple sources
2. **Set Up Correlation**: Cross-reference IOCs with your own threat hunting data
3. **Create Alerts**: Build detection rules based on high-confidence IOCs
4. **Integrate with SIEM**: Export IOCs to your SIEM platform

For advanced features, see:
- [Enrichment Service Documentation](./ENRICHMENT_SERVICE.md)
- [Correlation Engine Documentation](./CORRELATION_ENGINE.md)
- [API Reference](./API_REFERENCE.md)
