# Quick Start Guide - Threat Hunt Generator

Get up and running with the Automated Threat Hunt Generator in 5 minutes!

## Prerequisites

- Python 3.11+ OR Docker
- Git

## Option 1: Quick Start with Docker (Recommended)

### 1. Clone and Start

```bash
git clone <repository-url>
cd DetectiveSloth
docker-compose up -d
```

### 2. Initialize Database

```bash
docker exec -it threat_hunt_api python scripts/init_db.py
```

When prompted, type `y` to download MITRE ATT&CK data.

### 3. Access the API

Open your browser to: **http://localhost:8000/docs**

You now have a fully functional threat hunt generator!

## Option 2: Local Python Setup

### 1. Setup Environment

```bash
git clone <repository-url>
cd DetectiveSloth/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env if you want to use PostgreSQL, otherwise SQLite will be used
```

### 3. Initialize Database

```bash
python scripts/init_db.py
```

Type `y` when prompted to download MITRE ATT&CK data.

### 4. Run the API

```bash
uvicorn app.main:app --reload
```

Access at: **http://localhost:8000/docs**

## Your First Threat Hunt Query

### 1. Generate a Query for Process Injection (T1055)

```bash
curl -X POST "http://localhost:8000/api/queries/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "technique_ids": ["T1055"],
    "platforms": ["defender"],
    "timeframe": "7d"
  }'
```

### 2. Example Response

You'll receive a KQL query ready to run in Microsoft Defender:

```json
{
  "defender": {
    "query_id": 1,
    "query": "// MITRE ATT&CK T1055 - Process Injection Detection\nDeviceProcessEvents\n| where Timestamp > ago(7d)\n...",
    "metadata": {
      "confidence": "high",
      "false_positive_notes": "May trigger on legitimate debugging tools..."
    },
    "technique": {
      "id": "T1055",
      "name": "Process Injection",
      "tactics": ["Defense Evasion", "Privilege Escalation"]
    }
  }
}
```

## Common Use Cases

### Search for Techniques

```bash
# Find credential dumping techniques
curl "http://localhost:8000/api/techniques?keyword=credential"

# Get techniques by tactic
curl "http://localhost:8000/api/techniques?tactic=Persistence"
```

### Update Threat Intelligence

```bash
# Update all feeds (requires API keys in .env)
curl -X POST "http://localhost:8000/api/threat-intel/update"

# Update individual feeds
curl -X POST "http://localhost:8000/api/threat-intel/update/urlhaus"
curl -X POST "http://localhost:8000/api/threat-intel/update/threatfox"
```

### Create a Hunt Campaign

```bash
curl -X POST "http://localhost:8000/api/campaigns" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Ransomware Hunt October 2024",
    "techniques": ["T1055", "T1003", "T1059.001"],
    "threat_actor": "Ransomware",
    "analyst": "security@company.com"
  }'
```

### Generate Multi-Platform Queries

```bash
curl -X POST "http://localhost:8000/api/queries/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "technique_ids": ["T1059.001"],
    "platforms": ["defender", "crowdstrike", "carbonblack"],
    "timeframe": "24h",
    "include_iocs": true
  }'
```

## Available Endpoints

**Explore all endpoints at:** http://localhost:8000/docs

### Key Endpoints:

- `GET /api/techniques` - List MITRE techniques
- `POST /api/queries/generate` - Generate hunt queries
- `GET /api/threat-intel/recent` - Get recent IOCs
- `POST /api/campaigns` - Create hunt campaigns
- `POST /api/techniques/update` - Update MITRE data

## Pre-loaded Templates

The system comes with templates for:

- **T1055** - Process Injection (Defender, CrowdStrike)
- **T1003** - Credential Dumping (Defender, CrowdStrike)
- **T1059.001** - PowerShell Execution (Defender, Carbon Black)
- **T1053** - Scheduled Tasks (Defender, SentinelOne)
- **T1021.001** - RDP Access (Defender)

## Threat Intelligence Feeds

### Supported Feeds:

1. **AlienVault OTX** (requires API key)
2. **URLhaus** (Abuse.ch) - No API key needed
3. **ThreatFox** (Abuse.ch) - No API key needed

### Configure API Keys

Edit `.env` file:

```env
# AlienVault OTX (optional but recommended)
OTX_API_KEY=your-api-key-here

# VirusTotal (optional)
VIRUSTOTAL_API_KEY=your-vt-api-key
```

Get API keys:
- AlienVault OTX: https://otx.alienvault.com/api
- VirusTotal: https://www.virustotal.com/gui/my-apikey

## Next Steps

1. **Add More Templates**: Use `POST /api/queries/templates` to add your own
2. **Customize Queries**: Edit templates in `backend/app/templates/initial_templates.py`
3. **Schedule Updates**: Set up Celery for automated feed updates (Phase 2)
4. **Build UI**: Deploy the web interface (Phase 5)

## Troubleshooting

### Database Connection Issues

If using PostgreSQL and getting connection errors:

```bash
# Check if PostgreSQL is running
docker-compose ps

# View logs
docker-compose logs postgres
```

### MITRE Data Download Fails

Manually download MITRE data:

```bash
curl -X POST "http://localhost:8000/api/techniques/update"
```

### Port Already in Use

Change the port in `docker-compose.yml` or `.env`:

```yaml
ports:
  - "8080:8000"  # Change 8000 to 8080
```

## Getting Help

- **API Documentation**: http://localhost:8000/docs
- **Full Documentation**: See [README.md](README.md)
- **Project Plan**: See [automated-threat-hunt-generator-plan.md](automated-threat-hunt-generator-plan.md)

## What's Next?

Check the project plan for upcoming features:
- Phase 2: Enhanced threat intelligence processing
- Phase 3: More query templates (100+ techniques)
- Phase 4: Advanced query generation with ML
- Phase 5: Web dashboard
- Phase 6: Direct EDR integration
- Phase 7: MCP server for Claude

---

**Ready to hunt threats? Start generating queries!** 🎯
