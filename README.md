# Automated Threat Hunt Generator

> Generate platform-specific threat hunting queries from MITRE ATT&CK techniques and current threat intelligence

## Overview

The Automated Threat Hunt Generator is a system that automatically generates threat hunting queries for various EDR platforms (Microsoft Defender, CrowdStrike, Carbon Black, SentinelOne) based on:

- MITRE ATT&CK techniques and tactics
- Current threat intelligence feeds (AlienVault OTX, Abuse.ch, etc.)
- Pre-built query templates with variable substitution
- Real-time IOC enrichment

## Features

### Phase 1 - Foundation & Architecture ✅ COMPLETED

**Core Components:**
- MITRE ATT&CK integration with automatic updates
- Threat intelligence ingestion from multiple feeds
- Query generation engine with Jinja2 templates
- Database schema for techniques, IOCs, templates, and campaigns
- RESTful API with FastAPI
- Initial query templates for common techniques

**Supported EDR Platforms:**
- Microsoft Defender XDR (KQL)
- CrowdStrike (Humio/LogScale)
- Carbon Black Cloud
- SentinelOne Deep Visibility

### Phase 2 - Intelligence Processing ✅ COMPLETED

**Advanced Intelligence Features:**
- IOC enrichment with multi-factor risk scoring (prevalence, recency, credibility)
- Automated deduplication across threat feeds
- NLP-based TTP extraction from unstructured text (4 extraction methods)
- CVE correlation with exploit activity and MITRE techniques
- Threat actor profiling and TTP aggregation
- Intelligence scoring and prioritization system

**Enhanced Threat Intelligence Sources:**
- AlienVault OTX (community threat intelligence)
- URLhaus (Abuse.ch - malicious URLs)
- ThreatFox (Abuse.ch - multi-IOC types)
- CISA Known Exploited Vulnerabilities (KEV catalog)
- GreyNoise (internet scanner detection)

## Quick Start

### Prerequisites

- Python 3.11 or higher
- PostgreSQL (or SQLite for development)
- Git

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd DetectiveSloth
```

2. **Set up Python environment**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your database credentials and API keys
```

4. **Initialize database**
```bash
python scripts/init_db.py
```

This will:
- Create all database tables
- Seed initial query templates
- Optionally download MITRE ATT&CK data

5. **Run the API server**
```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

Interactive API documentation: `http://localhost:8000/docs`

## Usage

### 1. Update MITRE ATT&CK Data

```bash
curl -X POST http://localhost:8000/api/techniques/update
```

### 2. Update Threat Intelligence Feeds

```bash
# Update all feeds
curl -X POST http://localhost:8000/api/threat-intel/update

# Or update individual feeds
curl -X POST http://localhost:8000/api/threat-intel/update/otx
curl -X POST http://localhost:8000/api/threat-intel/update/urlhaus
curl -X POST http://localhost:8000/api/threat-intel/update/threatfox
curl -X POST http://localhost:8000/api/threat-intel/update/cisa-kev
curl -X POST http://localhost:8000/api/threat-intel/update/greynoise
```

### 3. Generate Threat Hunting Queries

```bash
curl -X POST http://localhost:8000/api/queries/generate \
  -H "Content-Type: application/json" \
  -d '{
    "technique_ids": ["T1055", "T1003"],
    "platforms": ["defender", "crowdstrike"],
    "timeframe": "7d",
    "include_iocs": true
  }'
```

### 4. Search Techniques

```bash
# Search by keyword
curl "http://localhost:8000/api/techniques?keyword=credential"

# Filter by tactic
curl "http://localhost:8000/api/techniques?tactic=Credential%20Access"

# Filter by platform
curl "http://localhost:8000/api/techniques?platform=Windows"
```

### 5. Create Hunt Campaigns

```bash
curl -X POST http://localhost:8000/api/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Qbot Campaign Hunt",
    "description": "Hunt for Qbot activity based on recent intelligence",
    "techniques": ["T1055", "T1003", "T1059.001"],
    "threat_actor": "Qbot",
    "analyst": "analyst@company.com"
  }'
```

## API Endpoints

### Techniques
- `GET /api/techniques` - List techniques with filters
- `GET /api/techniques/{technique_id}` - Get specific technique
- `GET /api/techniques/meta/tactics` - List all tactics
- `GET /api/techniques/meta/platforms` - List all platforms
- `POST /api/techniques/update` - Update MITRE data

### Query Generation
- `POST /api/queries/generate` - Generate queries
- `POST /api/queries/templates` - Add new template
- `GET /api/queries/templates/{technique_id}` - Get templates for technique

### Threat Intelligence
- `GET /api/threat-intel/recent` - Get recent IOCs
- `GET /api/threat-intel/by-technique/{technique_id}` - Get IOCs for technique
- `POST /api/threat-intel/update` - Update all feeds
- `POST /api/threat-intel/update/{feed}` - Update specific feed

### Campaigns
- `POST /api/campaigns` - Create campaign
- `GET /api/campaigns` - List campaigns
- `GET /api/campaigns/{id}` - Get campaign details
- `PATCH /api/campaigns/{id}` - Update campaign
- `DELETE /api/campaigns/{id}` - Delete campaign

### Intelligence Enrichment (Phase 2)
- `POST /api/enrichment/ioc` - Enrich single IOC
- `POST /api/enrichment/bulk` - Bulk IOC enrichment
- `POST /api/enrichment/deduplicate` - Remove duplicate IOCs
- `GET /api/enrichment/top-iocs` - Get highest risk IOCs
- `POST /api/enrichment/extract-ttps` - Extract TTPs from text
- `POST /api/enrichment/analyze-report` - Analyze threat report
- `POST /api/enrichment/enrich-with-ttps/{ioc}` - TTP enrichment for IOC

### CVE Management (Phase 2)
- `GET /api/cves` - List CVEs with filters
- `GET /api/cves/{cve_id}` - Get CVE details
- `POST /api/cves/correlate` - Correlate CVE with exploits
- `POST /api/cves/correlate-all` - Bulk CVE correlation
- `POST /api/cves/enrich` - Enrich CVE from NVD
- `GET /api/cves/high-risk` - Get high-risk CVEs
- `GET /api/cves/by-technique/{id}` - CVEs by MITRE technique
- `GET /api/cves/remediation-required` - CVEs needing remediation

### Threat Actor Profiling (Phase 2)
- `POST /api/threat-actors` - Create/update threat actor
- `GET /api/threat-actors` - List threat actors
- `GET /api/threat-actors/{name}` - Get actor details
- `POST /api/threat-actors/build-profile` - Build profile from IOCs
- `GET /api/threat-actors/active/recent` - Recently active actors
- `GET /api/threat-actors/by-technique/{id}` - Actors using technique
- `GET /api/threat-actors/by-sector/{sector}` - Actors targeting sector
- `POST /api/threat-actors/compare` - Compare two actors
- `GET /api/threat-actors/{name}/report` - Generate intelligence report

## Database Schema

```sql
-- MITRE ATT&CK techniques
mitre_techniques (id, technique_id, name, description, tactics[], platforms[], ...)

-- Threat intelligence
threat_intel (id, source, ioc_type, ioc_value, context, associated_techniques[], ...)

-- Query templates
detection_templates (id, technique_id, platform, query_template, variables, confidence, ...)

-- Generated queries
generated_queries (id, technique_ids[], platform, query_text, metadata, created_at, ...)

-- Hunt campaigns
hunt_campaigns (id, name, description, techniques[], threat_actor, status, findings, ...)

-- CVE tracking (Phase 2)
cves (id, cve_id, description, cvss_score, severity, exploited_in_wild, ransomware_use,
      associated_techniques[], remediation_deadline, ...)

-- Threat actor profiles (Phase 2)
threat_actors (id, name, aliases[], actor_type, motivation, techniques[], tactics[],
               targeted_sectors[], targeted_countries[], ...)

-- IOC enrichment (Phase 2)
ioc_enrichments (id, ioc_value, ioc_type, risk_score, prevalence_score, recency_score,
                 source_credibility_score, threat_families[], threat_actors[],
                 extracted_ttps[], ...)
```

## Configuration

### Environment Variables

Key environment variables in `.env`:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/threat_hunt_db

# Threat Intel API Keys
OTX_API_KEY=your-otx-api-key
VIRUSTOTAL_API_KEY=your-vt-api-key  # Optional
GREYNOISE_API_KEY=your-greynoise-api-key  # Optional (Phase 2)

# Update Intervals (hours)
MITRE_UPDATE_INTERVAL=24
THREAT_INTEL_UPDATE_INTERVAL=6

# Query Settings
DEFAULT_TIMEFRAME=7d
MAX_QUERY_RESULTS=1000
```

## Example Query Output

When you request a query for **T1055 (Process Injection)** on **Microsoft Defender**:

```kql
// MITRE ATT&CK T1055 - Process Injection Detection
// Confidence: High
// Timeframe: 7d

DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "QueueUserAPC", "SetWindowsHookEx", "NtMapViewOfSection"
)
or InitiatingProcessFileName in~ (
    "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"
)
| summarize
    InjectionCount = count(),
    UniqueTargets = dcount(FileName),
    Commands = make_set(ProcessCommandLine, 5)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where InjectionCount > 2
| project Timestamp, DeviceName, Injector = InitiatingProcessFileName,
    InjectionCount, UniqueTargets, SampleCommands = Commands
| order by Timestamp desc
```

The query includes:
- Technique context and metadata
- Platform-specific syntax
- Variable substitution (timeframe, IOCs)
- False positive guidance
- Confidence rating

## Development

### Project Structure

```
DetectiveSloth/
├── backend/
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── core/         # Config, database
│   │   ├── models/       # SQLAlchemy models
│   │   ├── services/     # Business logic
│   │   └── templates/    # Query templates
│   ├── scripts/          # Utility scripts
│   └── tests/            # Test suite
├── data/                 # Data files
├── frontend/             # Web UI (future)
└── docs/                 # Documentation
```

### Adding New Templates

You can add templates via the API or directly in code:

```python
from app.services.query_generator import QueryGenerator

generator = QueryGenerator(db)
generator.add_template(
    technique_id="T1053",
    platform="defender",
    query_template="""// Your KQL query here
    DeviceProcessEvents
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine contains "/create"
    """,
    confidence="medium",
    data_sources_required=["Process", "Command Line"]
)
```

### Running Tests

```bash
pytest tests/
```

## Roadmap

- [x] Phase 1: Foundation & Architecture
- [x] Phase 2: Intelligence Processing (Enhanced NLP, IOC Enrichment, CVE Correlation, Threat Actor Profiling)
- [ ] Phase 3: Additional Query Templates
- [ ] Phase 4: Advanced Query Generation
- [ ] Phase 5: Web UI
- [ ] Phase 6: EDR Integration & SIEM Export
- [ ] Phase 7: MCP Server for Claude Integration

See [automated-threat-hunt-generator-plan.md](automated-threat-hunt-generator-plan.md) for detailed roadmap.
See [PHASE2_COMPLETE.md](PHASE2_COMPLETE.md) for Phase 2 details.

## Contributing

Contributions welcome! Areas of focus:
- Additional query templates for more techniques
- Support for additional EDR platforms
- Query optimization and false positive reduction
- Integration with more threat intelligence feeds

## License

MIT License - See LICENSE file for details

## Security Note

This tool generates threat hunting queries based on threat intelligence. Always:
- Validate queries in a test environment first
- Review IOCs before deployment
- Follow your organization's security policies
- Protect API keys and credentials

## Support

For issues and questions:
- GitHub Issues: [Create an issue](../../issues)
- Documentation: [See docs/](docs/)

---

Built with ❤️ for threat hunters and security analysts
