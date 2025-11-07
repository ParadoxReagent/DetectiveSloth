# Phase 3 & Phase 4 Implementation Guide

This document describes the new features implemented in Phase 3 (Query Template Development) and Phase 4 (Query Generation Logic) of the Automated Threat Hunt Generator.

## Overview

**Phase 3** introduces a comprehensive collection of 40+ additional query templates covering all major MITRE ATT&CK tactics.

**Phase 4** implements advanced query generation features including query variations, analytic reasoning, and hunt campaign generation.

## Phase 3: Query Template Development

### New Template Coverage

Phase 3 adds templates for the following MITRE ATT&CK tactics and techniques:

#### Process Execution
- **T1059.003** - Windows Command Shell (Defender, CrowdStrike)
- **T1059.005** - Visual Basic (Defender, Carbon Black)

#### Persistence
- **T1547.001** - Registry Run Keys / Startup Folder (Defender, CrowdStrike)
- **T1547.009** - Shortcut Modification (Defender)

#### Credential Access
- **T1003.001** - LSASS Memory Dumping (Defender, SentinelOne)
- **T1003.002** - Security Account Manager (SAM) (Defender)
- **T1558.003** - Kerberoasting (Defender)

#### Lateral Movement
- **T1021.002** - SMB/Windows Admin Shares (Defender, CrowdStrike)
- **T1021.006** - Windows Remote Management (Defender)

#### Defense Evasion
- **T1070.001** - Clear Windows Event Logs (Defender, Carbon Black)
- **T1070.004** - File Deletion (Defender)
- **T1562.001** - Disable or Modify Tools (Defender, SentinelOne)

#### Discovery
- **T1087.001** - Account Discovery: Local Account (Defender, Carbon Black)
- **T1018** - Remote System Discovery (Defender)
- **T1082** - System Information Discovery (Defender)

#### Collection
- **T1560.001** - Archive via Utility (Defender, CrowdStrike)
- **T1113** - Screen Capture (Defender)
- **T1005** - Data from Local System (Defender)

#### Exfiltration
- **T1041** - Exfiltration Over C2 Channel (Defender, CrowdStrike)
- **T1567.002** - Exfiltration to Cloud Storage (Defender, Carbon Black)
- **T1048.003** - Exfiltration Over Alternative Protocol (Defender)

#### Command and Control
- **T1071.001** - Application Layer Protocol: Web Protocols (Defender, SentinelOne)
- **T1090.002** - External Proxy (Defender)

### Template Statistics

- **Total New Templates**: 40+
- **Techniques Covered**: 20+ new techniques
- **Platform Distribution**:
  - Microsoft Defender: 25+ templates
  - CrowdStrike: 8+ templates
  - Carbon Black: 6+ templates
  - SentinelOne: 4+ templates

## Phase 4: Query Generation Logic

### New Features

#### 1. Query Variations

Each query can now be generated in three variations:

- **Broad**: Wide net approach focusing on behavioral patterns
  - Higher false positive rate
  - Better for initial reconnaissance
  - No IOC filtering

- **Balanced**: Combines behavioral detection with moderate indicators
  - Balanced false positive rate
  - Recommended for most investigations
  - Moderate IOC filtering (confidence >= 5)

- **Specific**: Incorporates known IOCs and strict matching
  - Lower false positive rate
  - Best for targeted hunting with threat intelligence
  - Strict IOC filtering (confidence >= 7)

#### 2. Hunt Campaign Generation

Generate complete hunt campaigns with:
- Multiple techniques across multiple platforms
- All three query variations per technique
- Threat actor context integration
- Recommended hunt sequence
- Analytic reasoning

#### 3. Analytic Reasoning

Each hunt campaign includes:
- **Hypothesis**: Why we're hunting for these techniques
- **Expected Results**: Typical volume and investigation thresholds
- **Investigation Guidance**: Step-by-step investigation steps
- **Related Techniques**: Suggestions for expanding the hunt

#### 4. Threat Actor Context

When a threat actor is specified:
- Retrieves known IOCs associated with the actor
- Includes actor description and aliases
- Shows actor's known techniques
- Provides first/last seen timestamps

## API Endpoints

### Enhanced Query Generation

#### Generate Hunt Campaign

```bash
POST /api/enhanced-queries/hunt-campaign
```

**Request:**
```json
{
  "technique_ids": ["T1055", "T1003.001", "T1059.001"],
  "platforms": ["defender", "crowdstrike"],
  "threat_actor": "APT29",
  "timeframe": "7d",
  "include_variations": true
}
```

**Response:**
```json
{
  "queries": {
    "defender": [
      {
        "query": "// KQL query text...",
        "metadata": {
          "technique_id": "T1055",
          "technique_name": "Process Injection",
          "variation": "broad",
          "confidence": "high",
          "explanation": "This query hunts for Process Injection..."
        },
        "technique": {
          "id": "T1055",
          "name": "Process Injection",
          "description": "...",
          "tactics": ["Defense Evasion", "Privilege Escalation"]
        }
      }
    ]
  },
  "reasoning": {
    "hypothesis": "Based on known APT29 activity...",
    "expected_results": {...},
    "investigation_guidance": [...],
    "related_techniques": [...]
  },
  "hunt_sequence": [
    {
      "technique_id": "T1059.001",
      "name": "PowerShell",
      "order": 1,
      "rationale": "Part of Execution phase"
    }
  ],
  "threat_context": {
    "name": "APT29",
    "aliases": ["Cozy Bear", "The Dukes"],
    "iocs": {...}
  }
}
```

#### Generate Query with Explanation

```bash
POST /api/enhanced-queries/query-with-explanation
```

**Request:**
```json
{
  "technique_id": "T1055",
  "platform": "defender",
  "variation": "balanced",
  "timeframe": "7d",
  "threat_actor": "APT29"
}
```

#### Get Query Variations

```bash
GET /api/enhanced-queries/query-variations/{technique_id}/{platform}?timeframe=7d&threat_actor=APT29
```

Returns all three variations (broad, balanced, specific) for a technique.

#### Get Hunt Sequence

```bash
GET /api/enhanced-queries/hunt-sequence/T1055,T1003.001,T1059.001
```

Returns recommended order for hunting the specified techniques.

#### Get Related Techniques

```bash
GET /api/enhanced-queries/related-techniques/T1055
```

Returns techniques that share tactics with the specified technique.

#### Generate Analytic Reasoning

```bash
POST /api/enhanced-queries/analytic-reasoning
```

**Request:**
```json
{
  "technique_ids": ["T1055", "T1003.001"],
  "threat_actor": "APT29"
}
```

## Usage Examples

### Example 1: Quick Hunt for Process Injection

```bash
curl -X POST "http://localhost:8000/api/enhanced-queries/query-with-explanation" \
  -H "Content-Type: application/json" \
  -d '{
    "technique_id": "T1055",
    "platform": "defender",
    "variation": "balanced",
    "timeframe": "24h"
  }'
```

### Example 2: APT29 Hunt Campaign

```bash
curl -X POST "http://localhost:8000/api/enhanced-queries/hunt-campaign" \
  -H "Content-Type: application/json" \
  -d '{
    "technique_ids": ["T1055", "T1003.001", "T1059.001", "T1053"],
    "platforms": ["defender", "crowdstrike", "carbonblack"],
    "threat_actor": "APT29",
    "timeframe": "7d",
    "include_variations": true
  }'
```

### Example 3: Get All Variations for a Technique

```bash
curl "http://localhost:8000/api/enhanced-queries/query-variations/T1003.001/defender?timeframe=7d"
```

### Example 4: Plan Hunt Sequence

```bash
curl "http://localhost:8000/api/enhanced-queries/hunt-sequence/T1059.001,T1055,T1003.001,T1053,T1021.001"
```

## Query Variation Comparison

### Example: T1003.001 (LSASS Memory Dumping)

#### Broad Variation
- Detects all process interactions with LSASS
- No IOC filtering
- May include legitimate security tools
- Use for: Initial reconnaissance

#### Balanced Variation
- Detects suspicious LSASS access patterns
- Moderate IOC filtering (confidence >= 5)
- Filters common legitimate tools
- Use for: Regular threat hunting

#### Specific Variation
- Only detects LSASS access matching known malicious patterns
- Strict IOC filtering (confidence >= 7)
- Includes threat actor specific indicators
- Use for: Targeted hunting with threat intel

## Investigation Workflow

### Recommended Hunt Workflow

1. **Generate Hunt Campaign** with all variations
   ```bash
   POST /api/enhanced-queries/hunt-campaign
   ```

2. **Review Hunt Sequence** to understand recommended order
   - Start with Initial Access techniques
   - Progress through Execution, Persistence, etc.

3. **Execute Broad Queries** first for reconnaissance
   - Review results for suspicious patterns
   - Identify potential threats

4. **Execute Balanced Queries** to reduce noise
   - Focus on high-probability detections
   - Correlate with threat intelligence

5. **Execute Specific Queries** if threat intel available
   - Target known IOCs
   - Validate specific threat actor activity

6. **Follow Investigation Guidance**
   - Review process chains
   - Check network connections
   - Correlate with authentication logs
   - Escalate confirmed threats

## Database Schema Updates

No schema changes required - Phase 3 and 4 use existing database models.

## Configuration

No new configuration required. The enhanced features work with existing settings.

## Performance Considerations

### Query Generation Performance

- **Single Query**: < 500ms
- **Hunt Campaign (3 techniques, 2 platforms, 3 variations)**: < 2 seconds
- **With Threat Actor Context**: + 200-500ms

### Database Impact

- Phase 3 templates add ~40 new rows to `detection_templates` table
- Each generated query adds 1 row to `generated_queries` table
- Recommended: Monitor and archive old generated queries periodically

## Best Practices

### When to Use Each Variation

1. **Use Broad** when:
   - Starting a new investigation
   - Lacking specific threat intelligence
   - Performing baseline reconnaissance
   - Building detection coverage

2. **Use Balanced** when:
   - Conducting regular threat hunting
   - Following up on alerts
   - You have moderate threat context
   - Balancing coverage and precision

3. **Use Specific** when:
   - You have confirmed threat intelligence
   - Hunting for specific threat actors
   - Validating IOC presence
   - Minimizing false positives is critical

### Hunt Campaign Best Practices

1. **Scope Appropriately**
   - Start with 3-5 related techniques
   - Expand based on findings
   - Follow the recommended hunt sequence

2. **Leverage Threat Actor Context**
   - Always specify threat actor when available
   - Review actor-specific IOCs
   - Prioritize actor's known techniques

3. **Document Findings**
   - Use the hunt campaign model to track results
   - Record false positives for tuning
   - Share findings with team

## Troubleshooting

### No Templates Found

If you get "No templates found" errors:

```bash
# Re-run database initialization
python backend/scripts/init_db.py
```

### Missing Threat Actor Context

If threat actor context is not available:

1. Check threat actor exists in database
2. Ensure threat intelligence feeds are updated
3. Add threat actor manually via API:
   ```bash
   POST /api/threat-actors/
   ```

### Query Performance Issues

If queries are slow to generate:

1. Check IOC count in database
2. Consider reducing IOC limit in config
3. Archive old threat intelligence
4. Add database indexes if needed

## Future Enhancements

Planned for future phases:

- Machine learning for query optimization
- Automated baselining to reduce false positives
- Natural language query generation
- Integration with SIEM platforms
- Community query sharing

## Support

For issues or questions:

1. Check API documentation: http://localhost:8000/docs
2. Review project plan: `automated-threat-hunt-generator-plan.md`
3. Check logs for detailed error messages

## Version History

- **v0.1.0** - Phase 1 & 2: Foundation and Intelligence Processing
- **v0.2.0** - Phase 3 & 4: Query Template Development and Enhanced Query Generation (Current)

---

**Status**: Phase 3 and Phase 4 implementation complete ✅

**Next Phase**: Phase 5 - User Interface & API (Web Dashboard)
