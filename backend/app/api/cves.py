"""API endpoints for CVE management and correlation."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from ..core.database import get_db
from ..services.cve_correlation_service import CVECorrelationService

router = APIRouter(prefix="/api/cves", tags=["cves"])


class CorrelateCVERequest(BaseModel):
    """Request to correlate a CVE with exploits."""
    cve_id: str


class EnrichCVERequest(BaseModel):
    """Request to enrich CVE from NVD."""
    cve_id: str


@router.get("/")
async def list_cves(
    limit: int = 100,
    exploited_only: bool = False,
    ransomware_only: bool = False,
    db: Session = Depends(get_db)
):
    """List CVEs with optional filters."""
    from ..models.cve import CVE

    query = db.query(CVE)

    if exploited_only:
        query = query.filter(CVE.exploited_in_wild == True)

    if ransomware_only:
        query = query.filter(CVE.ransomware_use == True)

    cves = query.order_by(CVE.cvss_score.desc()).limit(limit).all()

    return {
        "count": len(cves),
        "cves": [
            {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "exploited_in_wild": cve.exploited_in_wild,
                "ransomware_use": cve.ransomware_use,
                "vendor": cve.vendor,
                "product": cve.product,
                "remediation_deadline": cve.remediation_deadline.isoformat() if cve.remediation_deadline else None,
            }
            for cve in cves
        ]
    }


@router.get("/{cve_id}")
async def get_cve(cve_id: str, db: Session = Depends(get_db)):
    """Get details for a specific CVE."""
    from ..models.cve import CVE

    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()

    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "cvss_score": cve.cvss_score,
        "severity": cve.severity,
        "vendor": cve.vendor,
        "product": cve.product,
        "affected_versions": cve.affected_versions,
        "published_date": cve.published_date.isoformat() if cve.published_date else None,
        "exploited_in_wild": cve.exploited_in_wild,
        "exploit_available": cve.exploit_available,
        "ransomware_use": cve.ransomware_use,
        "associated_techniques": cve.associated_techniques,
        "remediation_required": cve.remediation_required,
        "remediation_deadline": cve.remediation_deadline.isoformat() if cve.remediation_deadline else None,
        "vendor_advisory": cve.vendor_advisory,
        "references": cve.references,
        "context": cve.context,
    }


@router.post("/correlate")
async def correlate_cve(request: CorrelateCVERequest, db: Session = Depends(get_db)):
    """Correlate a CVE with exploits, IOCs, and techniques."""
    service = CVECorrelationService(db)
    results = await service.correlate_cve_with_exploits(request.cve_id)

    return results


@router.post("/correlate-all")
async def correlate_all_cves(limit: Optional[int] = None, db: Session = Depends(get_db)):
    """Correlate all CVEs with exploits and techniques."""
    service = CVECorrelationService(db)
    count = await service.correlate_all_cves(limit=limit)

    return {
        "status": "completed",
        "cves_correlated": count,
        "message": f"Successfully correlated {count} CVEs"
    }


@router.post("/enrich")
async def enrich_cve_from_nvd(request: EnrichCVERequest, db: Session = Depends(get_db)):
    """Enrich CVE data from NVD API."""
    service = CVECorrelationService(db)
    success = await service.enrich_cve_from_nvd(request.cve_id)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to enrich CVE from NVD")

    return {
        "status": "success",
        "message": f"Successfully enriched {request.cve_id} from NVD"
    }


@router.get("/high-risk")
async def get_high_risk_cves(limit: int = 50, db: Session = Depends(get_db)):
    """Get high-risk CVEs (exploited in wild or ransomware-used)."""
    service = CVECorrelationService(db)
    cves = service.get_high_risk_cves(limit=limit)

    return {
        "count": len(cves),
        "cves": [
            {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "exploited_in_wild": cve.exploited_in_wild,
                "ransomware_use": cve.ransomware_use,
                "remediation_deadline": cve.remediation_deadline.isoformat() if cve.remediation_deadline else None,
            }
            for cve in cves
        ]
    }


@router.get("/by-technique/{technique_id}")
async def get_cves_by_technique(technique_id: str, db: Session = Depends(get_db)):
    """Get CVEs associated with a MITRE technique."""
    service = CVECorrelationService(db)
    cves = service.get_cves_by_technique(technique_id)

    return {
        "technique_id": technique_id,
        "count": len(cves),
        "cves": [
            {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
            }
            for cve in cves
        ]
    }


@router.get("/remediation-required")
async def get_cves_requiring_remediation(db: Session = Depends(get_db)):
    """Get CVEs requiring immediate remediation."""
    service = CVECorrelationService(db)
    cves = service.get_cves_requiring_remediation()

    return {
        "count": len(cves),
        "cves": [
            {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "severity": cve.severity,
                "vendor": cve.vendor,
                "product": cve.product,
                "remediation_deadline": cve.remediation_deadline.isoformat() if cve.remediation_deadline else None,
                "days_remaining": (cve.remediation_deadline - __import__('datetime').datetime.utcnow()).days if cve.remediation_deadline else None,
            }
            for cve in cves
        ]
    }
