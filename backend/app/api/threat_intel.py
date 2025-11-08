"""Threat intelligence API endpoints."""

from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..core.database import get_db
from ..services.threat_intel_service import ThreatIntelService

router = APIRouter()


class IOCResponse(BaseModel):
    """Response model for IOC."""
    id: int
    source: str
    ioc_type: str
    ioc_value: str
    confidence_score: Optional[int]
    tags: List[str]
    associated_techniques: List[str]

    class Config:
        from_attributes = True


class UpdateResponse(BaseModel):
    """Response for update operations."""
    success: bool
    message: str
    results: Dict[str, int]


@router.get("/recent", response_model=List[IOCResponse])
async def get_recent_iocs(
    days: int = 7,
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get recent IOCs from threat intelligence feeds."""
    service = ThreatIntelService(db)
    iocs = service.get_recent_iocs(days=days, ioc_type=ioc_type, source=source)
    return iocs[skip:skip + limit]


@router.get("/by-technique/{technique_id}", response_model=List[IOCResponse])
async def get_iocs_by_technique(
    technique_id: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get IOCs associated with a specific MITRE technique."""
    service = ThreatIntelService(db)
    iocs = service.get_iocs_by_technique(technique_id)
    return iocs[skip:skip + limit]


@router.post("/update", response_model=UpdateResponse)
async def update_threat_intel(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Update threat intelligence from all feeds."""
    service = ThreatIntelService(db)

    try:
        results = await service.update_all_feeds()
        total = sum(results.values())

        return UpdateResponse(
            success=True,
            message=f"Successfully updated {total} indicators from {len(results)} feeds",
            results=results
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update threat intel: {str(e)}")


@router.post("/update/otx")
async def update_otx(days: int = 7, db: Session = Depends(get_db)):
    """Update IOCs from AlienVault OTX."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_otx_indicators(days=days)
        return {
            "success": True,
            "message": f"Successfully ingested {count} indicators from OTX",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update OTX: {str(e)}")


@router.post("/update/urlhaus")
async def update_urlhaus(db: Session = Depends(get_db)):
    """Update URLs from URLhaus."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_abusech_urlhaus()
        return {
            "success": True,
            "message": f"Successfully ingested {count} URLs from URLhaus",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update URLhaus: {str(e)}")


@router.post("/update/threatfox")
async def update_threatfox(db: Session = Depends(get_db)):
    """Update IOCs from ThreatFox."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_abusech_threatfox()
        return {
            "success": True,
            "message": f"Successfully ingested {count} IOCs from ThreatFox",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ThreatFox: {str(e)}")


@router.post("/update/cisa-kev")
async def update_cisa_kev(db: Session = Depends(get_db)):
    """Update CVEs from CISA Known Exploited Vulnerabilities catalog."""
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_cisa_kev()
        return {
            "success": True,
            "message": f"Successfully ingested {count} CVEs from CISA KEV",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update CISA KEV: {str(e)}")


@router.post("/update/greynoise")
async def update_greynoise(classification: str = "malicious", db: Session = Depends(get_db)):
    """Update IPs from GreyNoise.

    Args:
        classification: Filter by classification (malicious, benign, unknown)
    """
    service = ThreatIntelService(db)

    try:
        count = await service.ingest_greynoise(classification=classification)
        return {
            "success": True,
            "message": f"Successfully ingested {count} IPs from GreyNoise",
            "count": count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update GreyNoise: {str(e)}")


@router.post("/update/virustotal")
async def update_virustotal(limit: int = 100, db: Session = Depends(get_db)):
    """Update IOCs from VirusTotal."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_virustotal_iocs(limit=limit)
        return {"success": True, "message": f"Successfully ingested {count} IOCs from VirusTotal", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update VirusTotal: {str(e)}")


@router.post("/update/hybrid-analysis")
async def update_hybrid_analysis(days: int = 7, db: Session = Depends(get_db)):
    """Update sandbox reports from Hybrid Analysis."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_hybrid_analysis(days=days)
        return {"success": True, "message": f"Successfully ingested {count} IOCs from Hybrid Analysis", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Hybrid Analysis: {str(e)}")


@router.post("/update/shodan")
async def update_shodan(query: str = "has_vuln:true", limit: int = 100, db: Session = Depends(get_db)):
    """Update exposed services from Shodan."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_shodan(query=query, limit=limit)
        return {"success": True, "message": f"Successfully ingested {count} IPs from Shodan", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Shodan: {str(e)}")


@router.post("/update/abuseipdb")
async def update_abuseipdb(days: int = 7, confidence_min: int = 75, db: Session = Depends(get_db)):
    """Update malicious IPs from AbuseIPDB."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_abuseipdb(days=days, confidence_min=confidence_min)
        return {"success": True, "message": f"Successfully ingested {count} IPs from AbuseIPDB", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update AbuseIPDB: {str(e)}")


@router.post("/update/phishtank")
async def update_phishtank(db: Session = Depends(get_db)):
    """Update phishing URLs from PhishTank."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_phishtank()
        return {"success": True, "message": f"Successfully ingested {count} URLs from PhishTank", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update PhishTank: {str(e)}")


@router.post("/update/malware-bazaar")
async def update_malware_bazaar(db: Session = Depends(get_db)):
    """Update malware samples from MalwareBazaar."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_malware_bazaar()
        return {"success": True, "message": f"Successfully ingested {count} samples from MalwareBazaar", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update MalwareBazaar: {str(e)}")


@router.post("/update/feodo-tracker")
async def update_feodo_tracker(db: Session = Depends(get_db)):
    """Update C2 servers from Feodo Tracker."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_feodo_tracker()
        return {"success": True, "message": f"Successfully ingested {count} C2 IPs from Feodo Tracker", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Feodo Tracker: {str(e)}")


@router.post("/update/sslbl")
async def update_sslbl(db: Session = Depends(get_db)):
    """Update malicious SSL certificates from SSL Blacklist."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_sslbl()
        return {"success": True, "message": f"Successfully ingested {count} items from SSL Blacklist", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update SSL Blacklist: {str(e)}")


@router.post("/update/urlscan")
async def update_urlscan(limit: int = 100, db: Session = Depends(get_db)):
    """Update malicious URLs from URLScan.io."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_urlscan(limit=limit)
        return {"success": True, "message": f"Successfully ingested {count} URLs from URLScan.io", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update URLScan.io: {str(e)}")


@router.post("/update/pulsedive")
async def update_pulsedive(risk: str = "high", db: Session = Depends(get_db)):
    """Update threat intelligence from Pulsedive."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_pulsedive(risk=risk)
        return {"success": True, "message": f"Successfully ingested {count} IOCs from Pulsedive", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Pulsedive: {str(e)}")


@router.post("/update/blocklist-de")
async def update_blocklist_de(db: Session = Depends(get_db)):
    """Update brute force IPs from Blocklist.de."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_blocklist_de()
        return {"success": True, "message": f"Successfully ingested {count} IPs from Blocklist.de", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Blocklist.de: {str(e)}")


@router.post("/update/spamhaus-drop")
async def update_spamhaus_drop(db: Session = Depends(get_db)):
    """Update netblocks from Spamhaus DROP/EDROP lists."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_spamhaus_drop()
        return {"success": True, "message": f"Successfully ingested {count} netblocks from Spamhaus DROP", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update Spamhaus DROP: {str(e)}")


@router.post("/update/misp")
async def update_misp(instance_url: Optional[str] = None, api_key: Optional[str] = None, days: int = 7, db: Session = Depends(get_db)):
    """Update threat intelligence from MISP instance."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_misp(instance_url=instance_url, api_key=api_key, days=days)
        return {"success": True, "message": f"Successfully ingested {count} IOCs from MISP", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update MISP: {str(e)}")


@router.post("/update/opencti")
async def update_opencti(instance_url: Optional[str] = None, api_key: Optional[str] = None, limit: int = 100, db: Session = Depends(get_db)):
    """Update threat intelligence from OpenCTI instance."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_opencti(instance_url=instance_url, api_key=api_key, limit=limit)
        return {"success": True, "message": f"Successfully ingested {count} IOCs from OpenCTI", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update OpenCTI: {str(e)}")


@router.post("/update/rss-feeds")
async def update_rss_feeds(feeds: Optional[List[str]] = None, db: Session = Depends(get_db)):
    """Update threat intelligence from RSS/Atom feeds."""
    service = ThreatIntelService(db)
    try:
        count = await service.ingest_rss_feeds(feeds=feeds)
        return {"success": True, "message": f"Successfully ingested {count} RSS feed items", "count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update RSS feeds: {str(e)}")
