# Automated Threat Hunt Generator - Project Plan

## Project Overview
A system that automatically generates platform-specific threat hunting queries (KQL, CrowdStrike, Carbon Black, SentinelOne) based on MITRE ATT&CK techniques and current threat intelligence feeds.

## Implementation Status

### ✅ Phase 1: Foundation & Architecture - **COMPLETED**
- ✅ Project structure and core files
- ✅ Database models and schema (SQLAlchemy ORM)
- ✅ MITRE ATT&CK integration module (STIX parsing)
- ✅ Threat intelligence ingestion (OTX, URLhaus, ThreatFox)
- ✅ Query generation engine (Jinja2 templates)
- ✅ RESTful API with FastAPI
- ✅ Initial query templates (10+ templates for common techniques)
- ✅ Docker deployment setup
- ✅ Documentation and README

**Files Created:**
- Backend application structure (`/backend/app/`)
- Database models (threat_intel, mitre_techniques, detection_templates, generated_queries, hunt_campaigns)
- Services (MitreAttackService, ThreatIntelService, QueryGenerator)
- API endpoints (techniques, queries, threat_intel, campaigns)
- Configuration and dependencies
- Initial templates and seed scripts
- Docker setup (docker-compose.yml, Dockerfile)

### ✅ Phase 2: Intelligence Processing - **COMPLETED**
**Completed:** Comprehensive threat intelligence ingestion, TTP extraction, CVE correlation, and IOC enrichment services.

**Key Features:**
- Multiple threat feed integration (OTX, URLhaus, ThreatFox, CISA KEV)
- Threat actor tracking and profiling
- CVE correlation with MITRE techniques
- IOC enrichment and deduplication
- TTP extraction from threat reports

### ✅ Phase 3: Query Template Development - **COMPLETED**
**Completed:** Comprehensive query template library covering all major MITRE ATT&CK tactics.

**Key Features:**
- 40+ new query templates across all major tactics
- Coverage for 20+ additional MITRE techniques
- Multi-platform support (Defender, CrowdStrike, Carbon Black, SentinelOne)
- Templates for Process Execution, Persistence, Credential Access, Lateral Movement, Defense Evasion, Discovery, Collection, Exfiltration, and Command & Control

**Files Created:**
- `/backend/app/templates/phase3_templates.py` - Comprehensive template collection

### ✅ Phase 4: Query Generation Logic - **COMPLETED**
**Completed:** Advanced query generation with variations, analytic reasoning, and hunt campaign support.

**Key Features:**
- Query variations (broad, balanced, specific) for flexible hunting
- Hunt campaign generation with multi-technique support
- Analytic reasoning and hypothesis generation
- Threat actor context integration
- Recommended hunt sequence based on attack progression
- Investigation guidance and related technique suggestions
- Enhanced IOC integration with confidence filtering

**Files Created:**
- `/backend/app/services/enhanced_query_generator.py` - Advanced query generation engine
- `/backend/app/api/enhanced_queries.py` - Enhanced API endpoints
- `/PHASE3_PHASE4_FEATURES.md` - Comprehensive feature documentation

**API Endpoints Added:**
- `POST /api/enhanced-queries/hunt-campaign` - Generate complete hunt campaigns
- `POST /api/enhanced-queries/query-with-explanation` - Generate queries with detailed explanations
- `GET /api/enhanced-queries/query-variations/{technique_id}/{platform}` - Get all query variations
- `GET /api/enhanced-queries/hunt-sequence/{technique_ids}` - Get recommended hunt sequence
- `GET /api/enhanced-queries/related-techniques/{technique_id}` - Find related techniques
- `POST /api/enhanced-queries/analytic-reasoning` - Generate analytic reasoning

### 🔄 Phase 5: User Interface & API - Not Started
### 🔄 Phase 6: Advanced Features - Not Started
### 🔄 Phase 7: MCP Server Development - Not Started

---

## Phase 1: Foundation & Architecture (Week 1-2) ✅ COMPLETED

### Core Components ✅

1. **Threat Intelligence Ingestion Module** ✅
   - ✅ Connect to threat intel feeds (AlienVault OTX, URLhaus, ThreatFox)
   - ✅ Parse and normalize threat data (IOCs, TTPs)
   - ✅ Store in structured format (PostgreSQL or SQLite)
   - ✅ API endpoints for feed updates (on-demand, scheduled for future)

2. **MITRE ATT&CK Integration** ✅
   - ✅ Download and parse MITRE ATT&CK framework (STIX format)
   - ✅ Map techniques to sub-techniques
   - ✅ Store technique metadata (data sources, tactics, platforms)
   - ✅ Create relationships between techniques and platforms
   - ✅ Search and filter capabilities

3. **Query Generation Engine** ✅
   - ✅ Template system for each EDR platform (Jinja2)
   - ✅ Logic to convert TTPs to platform-specific queries
   - ✅ Variable substitution (IOCs, time ranges, etc.)
   - ✅ Multi-platform query generation
   - ✅ IOC enrichment integration

4. **Database Schema** ✅
   ```
   ✅ threat_intel (id, source, ioc_type, ioc_value, context, associated_techniques, confidence_score, first_seen, last_seen, tags)
   ✅ mitre_techniques (id, technique_id, name, description, tactics, platforms, data_sources, detection_notes, mitigation_notes, version, updated_at)
   ✅ detection_templates (id, technique_id, platform, query_template, variables, confidence, false_positive_notes, data_sources_required, created_by, created_at, version)
   ✅ generated_queries (id, technique_ids, platform, query_text, metadata, created_at, executed, results_count)
   ✅ hunt_campaigns (id, name, description, techniques, threat_actor, start_date, end_date, status, findings, analyst)
   ```

**Implementation Details:**
- FastAPI REST API with full CRUD operations
- SQLAlchemy ORM models with proper relationships
- Async HTTP clients for feed ingestion
- 10+ initial query templates for common techniques (T1055, T1003, T1059.001, T1053, T1021.001)
- Support for 4 EDR platforms: Defender, CrowdStrike, Carbon Black, SentinelOne

---

## Phase 2: Intelligence Processing (Week 3-4)

### Threat Intel Feeds Integration
1. **Primary Feeds**
   - MITRE ATT&CK CTI (authoritative TTPs)
   - AlienVault OTX (community intel)
   - CISA Known Exploited Vulnerabilities
   - Abuse.ch (malware/C2 tracking)
   - GreyNoise (internet scanner detection)

2. **Intelligence Enrichment**
   - Deduplicate IOCs across feeds
   - Score/prioritize based on recency and source credibility
   - Extract associated MITRE techniques from reports
   - Correlate CVEs with exploit activity

3. **TTP Extraction**
   - Parse threat reports for TTPs
   - Use NLP/LLM to extract techniques from unstructured reports
   - Map IOCs to specific MITRE techniques
   - Build threat actor profiles

---

## Phase 3: Query Template Development (Week 5-7)

### Platform-Specific Templates

**Microsoft Defender (KQL)**
```kql
// T1055 - Process Injection Detection
DeviceProcessEvents
| where Timestamp > ago({timeframe})
| where ProcessCommandLine contains_any ({suspicious_patterns})
| where InitiatingProcessFileName in~ ({known_injectors})
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**CrowdStrike (Humio)**
```
// T1003 - Credential Dumping
#event_simpleName=ProcessRollup2
| ComputerName=* CommandLine=/lsass|procdump|mimikatz/i
| groupBy([ComputerName, CommandLine], function=count())
```

**Carbon Black Cloud**
```
// T1059.001 - PowerShell Execution
process_name:powershell.exe AND (process_cmdline:"-enc" OR process_cmdline:"-encodedcommand")
AND (process_cmdline:"downloadstring" OR process_cmdline:"iex")
```

**SentinelOne (Deep Visibility)**
```
// T1053 - Scheduled Task Creation
EventType = "Scheduled Task" AND
(SrcProcCmdLine ContainsCIS "schtasks" OR SrcProcCmdLine ContainsCIS "at.exe")
```

### Template Categories
1. **Process Execution** (T1059.x)
2. **Persistence** (T1053, T1547.x)
3. **Credential Access** (T1003.x, T1558)
4. **Lateral Movement** (T1021.x)
5. **Defense Evasion** (T1070.x, T1562)
6. **Discovery** (T1087.x, T1018)
7. **Collection** (T1560, T1113)
8. **Exfiltration** (T1041, T1567)

---

## Phase 4: Query Generation Logic (Week 8-9)

### Generation Workflow
1. **Input Selection**
   - User selects MITRE technique(s) OR threat actor OR recent campaign
   - System identifies relevant detection methods
   - Retrieves associated IOCs from threat intel

2. **Template Matching**
   - Match technique to available templates per platform
   - Check data source availability (process, network, file, registry)
   - Prioritize high-confidence detections

3. **Query Customization**
   - Inject current IOCs (hashes, IPs, domains, filenames)
   - Set appropriate time ranges
   - Add context from threat intel (threat actor, campaign name)
   - Adjust thresholds based on environment

4. **Multi-Query Generation**
   - Create queries for all available EDR platforms
   - Generate variations (broad vs. specific)
   - Include analytic reasoning/explanation
   - Provide expected results and false positive guidance

---

## Phase 5: User Interface & API (Week 10-11)

### Web Interface
1. **Dashboard**
   - Recent threat intel summary
   - Active campaigns requiring hunts
   - Generated query statistics
   - Detection coverage heatmap (MITRE matrix)

2. **Query Generator Page**
   - MITRE ATT&CK technique selector (interactive matrix)
   - Threat actor/campaign dropdown
   - Platform multi-select (generate for multiple EDRs)
   - Time range selector
   - IOC filter/enrichment options

3. **Hunt Campaign Manager**
   - Create hunt campaigns targeting multiple techniques
   - Track hunt execution status
   - Document findings
   - Export reports

4. **Template Editor**
   - Add/modify query templates
   - Test queries against sample data
   - Version control for templates
   - Community sharing (optional)

### API Endpoints
```
POST /api/generate-query
  Body: {
    "technique_ids": ["T1055", "T1003.001"],
    "platforms": ["defender", "crowdstrike"],
    "timeframe": "7d",
    "ioc_types": ["hash", "domain"]
  }

GET /api/techniques?tactic=credential-access
GET /api/threat-intel/recent?days=7
POST /api/hunt-campaign
GET /api/templates?platform=defender
```

---

## Phase 6: Advanced Features (Week 12-14)

### Intelligence Features
1. **Hypothesis Generation**
   - Suggest related techniques to hunt for
   - Recommend hunt sequences (kill chain order)
   - Identify gaps in detection coverage

2. **Threat Actor Playbooks**
   - Pre-built hunt campaigns for known threat actors (APT29, Lazarus, etc.)
   - Automated query generation for new threat actor reports
   - TTP timeline visualization

3. **Query Optimization**
   - Analyze query performance
   - Suggest index improvements
   - Combine related queries for efficiency

### Integration Features
1. **EDR Platform Integration**
   - Direct query execution via APIs
   - Automated result collection
   - Finding deduplication across platforms

2. **SIEM/SOAR Integration**
   - Export queries to Splunk/Sentinel/Chronicle
   - Create SOAR playbooks from hunt findings
   - Automated ticket creation for hits

3. **Collaborative Features**
   - Share hunt campaigns with team
   - Annotate queries with notes
   - Track which hunts found actual threats

---

## Phase 7: MCP Server Development (Week 15-16)

### MCP Integration
Building on your existing MCP expertise, create an MCP server that exposes threat hunting capabilities to Claude:

```python
@mcp.tool()
async def generate_threat_hunt(
    technique_id: str,
    platforms: list[str],
    include_iocs: bool = True
) -> dict:
    """Generate threat hunting queries for MITRE ATT&CK technique"""
    # Your existing query generation logic
    
@mcp.tool()
async def search_techniques(
    keyword: str,
    tactic: Optional[str] = None
) -> list[dict]:
    """Search MITRE ATT&CK techniques"""
    
@mcp.tool()
async def get_threat_intel(
    ioc_type: str,
    days: int = 7
) -> list[dict]:
    """Get recent threat intelligence"""
```

This allows Claude to:
- Generate queries conversationally
- Explain detection logic
- Suggest hunt strategies
- Correlate findings across platforms

---

## Technology Stack Recommendations

### Backend
- **Python 3.11+** (your forte)
- **FastAPI** - REST API and web interface
- **SQLAlchemy** - Database ORM
- **PostgreSQL** - Main database
- **Redis** - Caching threat intel
- **Celery** - Scheduled intel updates
- **HTTPX** - Async HTTP for feed fetching

### Frontend
- **React or Vue.js** - Interactive UI
- **D3.js** - MITRE matrix visualization
- **Tailwind CSS** - Styling
- **Monaco Editor** - Query editor with syntax highlighting

### Libraries
- **STIX/TAXII** - Threat intel parsing
- **mitreattack-python** - ATT&CK framework access
- **Jinja2** - Query template rendering
- **Pydantic** - Data validation
- **python-dotenv** - Configuration

---

## Database Schema Details

```sql
-- Core threat intelligence
CREATE TABLE threat_intel (
    id SERIAL PRIMARY KEY,
    source VARCHAR(100),
    ioc_type VARCHAR(50),
    ioc_value TEXT,
    context JSONB,
    associated_techniques TEXT[],
    confidence_score INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    tags TEXT[]
);

-- MITRE ATT&CK techniques
CREATE TABLE mitre_techniques (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(20) UNIQUE,
    name VARCHAR(200),
    description TEXT,
    tactics TEXT[],
    platforms TEXT[],
    data_sources TEXT[],
    detection_notes TEXT,
    mitigation_notes TEXT,
    version VARCHAR(10),
    updated_at TIMESTAMP
);

-- Query templates
CREATE TABLE detection_templates (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(20),
    platform VARCHAR(50),
    query_template TEXT,
    variables JSONB,
    confidence VARCHAR(20),
    false_positive_notes TEXT,
    data_sources_required TEXT[],
    created_by VARCHAR(100),
    created_at TIMESTAMP,
    version INTEGER
);

-- Generated queries
CREATE TABLE generated_queries (
    id SERIAL PRIMARY KEY,
    technique_ids TEXT[],
    platform VARCHAR(50),
    query_text TEXT,
    metadata JSONB,
    created_at TIMESTAMP,
    executed BOOLEAN DEFAULT FALSE,
    results_count INTEGER
);

-- Hunt campaigns
CREATE TABLE hunt_campaigns (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200),
    description TEXT,
    techniques TEXT[],
    threat_actor VARCHAR(100),
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    status VARCHAR(50),
    findings JSONB,
    analyst VARCHAR(100)
);
```

---

## Sample Output Example

When a user selects **T1055 (Process Injection)**, the system generates:

**Microsoft Defender XDR (KQL)**
```kql
// MITRE ATT&CK T1055 - Process Injection Hunt
// Detection: Suspicious process hollowing and injection behaviors
// Confidence: High | False Positive: Medium

DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "QueueUserAPC", "SetWindowsHookEx"
) or InitiatingProcessFileName in~ (
    "powershell.exe", "rundll32.exe", "regsvr32.exe"
)
| where FileName !in~ ("known_legitimate_tools.exe")
| extend InjectionIndicators = pack_array(
    iff(ProcessCommandLine contains "VirtualAllocEx", "MemoryAlloc", ""),
    iff(ProcessCommandLine contains "WriteProcessMemory", "MemoryWrite", ""),
    iff(ProcessCommandLine contains "CreateRemoteThread", "RemoteThread", "")
)
| where array_length(InjectionIndicators) >= 2
| summarize 
    InjectionCount = count(),
    UniqueTargets = dcount(FileName),
    Commands = make_set(ProcessCommandLine, 5)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where InjectionCount > 2
| project 
    Timestamp, 
    DeviceName, 
    Injector = InitiatingProcessFileName,
    InjectionCount,
    UniqueTargets,
    SampleCommands = Commands
| order by Timestamp desc

// Expected Results: 2-10 events per day in typical environment
// Follow-up: Investigate parent process chain and network connections
// Related Techniques: T1059 (Command Execution), T1106 (Native API)
```

**CrowdStrike (Humio)**
```
// T1055 - Process Injection Detection
#event_simpleName=ProcessRollup2
| (ImageFileName=/powershell\.exe|rundll32\.exe/i 
   AND CommandLine=/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/i)
| groupBy([ComputerName, ImageFileName, CommandLine], function=[count(as=Events), collect([TargetProcessId])])
| Events > 1
```

**Context Panel**
- **Threat Intel**: Recent Qbot campaigns using process injection (last 48 hours)
- **Known IOCs**: 3 file hashes, 12 C2 domains associated with this technique
- **Recommended Hunt Sequence**: 
  1. T1055 (Process Injection) ← Start here
  2. T1071 (Application Layer Protocol) - Check C2 communication
  3. T1053 (Scheduled Task) - Check persistence

---

## Deployment Strategy

### Development Environment
```bash
# Docker Compose setup
services:
  api:
    build: ./backend
    ports: ["8000:8000"]
    depends_on: [postgres, redis]
    
  postgres:
    image: postgres:16
    volumes: ["./data:/var/lib/postgresql/data"]
    
  redis:
    image: redis:7-alpine
    
  celery:
    build: ./backend
    command: celery -A app.tasks worker -l info
    
  frontend:
    build: ./frontend
    ports: ["3000:3000"]
```

### Production Considerations
- Deploy behind reverse proxy (Nginx/Caddy)
- Use environment variables for API keys
- Implement rate limiting on threat intel feeds
- Set up monitoring (Prometheus + Grafana)
- Automated backups of database
- Consider Cloudflare Workers for MCP server hosting

---

## Success Metrics

1. **Coverage**: % of MITRE ATT&CK techniques with query templates (target: 70% of top 50 techniques)
2. **Accuracy**: Query false positive rate (target: <10%)
3. **Performance**: Query generation time (target: <2 seconds)
4. **Threat Intel Freshness**: IOC age (target: <24 hours for critical feeds)
5. **Usage**: Queries generated per week, hunts leading to findings

---

## Future Enhancements

- **Machine Learning**: Auto-tune query thresholds based on historical results
- **Natural Language Input**: "Show me ransomware activity in the last week"
- **Automated Baselining**: Learn normal behavior to reduce false positives
- **Threat Actor Attribution**: Automatically attribute findings to threat actors
- **Integration with Threat Briefing Services**: Auto-generate hunts from daily threat briefs
- **Community Query Sharing**: Platform for sharing effective detection queries

---

## Getting Started

### Phase 1 Quick Start
1. Set up Python virtual environment
2. Install core dependencies: `pip install fastapi sqlalchemy psycopg2-binary httpx`
3. Initialize PostgreSQL database
4. Download MITRE ATT&CK STIX data: `https://github.com/mitre/cti`
5. Create basic FastAPI app structure
6. Implement MITRE technique parser
7. Build first query template for one platform

### Recommended First Milestone
Build a minimal viable product that can:
- Ingest MITRE ATT&CK techniques (static file)
- Store 10 query templates for Defender XDR
- Generate a query for a selected technique
- Display results in simple web UI

This gives you a functional prototype to iterate on while building out the more complex threat intel ingestion and advanced features.

---

This project combines your cybersecurity expertise, query building experience, and MCP development skills into a powerful threat hunting automation tool. The modular architecture allows you to build incrementally, starting with core query generation and expanding into advanced threat intelligence integration and collaborative features.
