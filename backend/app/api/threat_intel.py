"""Threat intelligence API endpoints."""

from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from celery.result import AsyncResult

from ..core.database import get_db
from ..services.threat_intel_service import ThreatIntelService
from ..tasks.threat_intel_tasks import (
    update_all_feeds_task,
    update_otx_task,
    update_urlhaus_task,
    update_threatfox_task,
    update_cisa_kev_task,
    update_greynoise_task
)

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


class TaskResponse(BaseModel):
    """Response for background task operations."""
    task_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    """Response for task status check."""
    task_id: str
    status: str
    result: Optional[Dict] = None


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


@router.post("/update", response_model=TaskResponse)
async def update_threat_intel():
    """Update threat intelligence from all feeds (async background task)."""
    try:
        task = update_all_feeds_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message="Threat intelligence update started. Use /api/threat-intel/tasks/{task_id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start update task: {str(e)}")


@router.post("/update/otx", response_model=TaskResponse)
async def update_otx(days: int = 7):
    """Update IOCs from AlienVault OTX (async background task)."""
    try:
        task = update_otx_task.delay(days=days)
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"OTX update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start OTX update: {str(e)}")


@router.post("/update/urlhaus", response_model=TaskResponse)
async def update_urlhaus():
    """Update URLs from URLhaus (async background task)."""
    try:
        task = update_urlhaus_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"URLhaus update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start URLhaus update: {str(e)}")


@router.post("/update/threatfox", response_model=TaskResponse)
async def update_threatfox():
    """Update IOCs from ThreatFox (async background task)."""
    try:
        task = update_threatfox_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"ThreatFox update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start ThreatFox update: {str(e)}")


@router.post("/update/cisa-kev", response_model=TaskResponse)
async def update_cisa_kev():
    """Update CVEs from CISA Known Exploited Vulnerabilities catalog (async background task)."""
    try:
        task = update_cisa_kev_task.delay()
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"CISA KEV update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start CISA KEV update: {str(e)}")


@router.post("/update/greynoise", response_model=TaskResponse)
async def update_greynoise(classification: str = "malicious"):
    """Update IPs from GreyNoise (async background task).

    Args:
        classification: Filter by classification (malicious, benign, unknown)
    """
    try:
        task = update_greynoise_task.delay(classification=classification)
        return TaskResponse(
            task_id=task.id,
            status="processing",
            message=f"GreyNoise update started. Use /api/threat-intel/tasks/{task.id} to check status."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start GreyNoise update: {str(e)}")


@router.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Get the status of a background task."""
    try:
        task_result = AsyncResult(task_id)

        response = TaskStatusResponse(
            task_id=task_id,
            status=task_result.status.lower(),
            result=task_result.result if task_result.ready() else None
        )

        return response
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
