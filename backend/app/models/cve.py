"""CVE (Common Vulnerabilities and Exposures) model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, JSON, ARRAY, Boolean, Float
from ..core.database import Base


class CVE(Base):
    """CVE tracking with exploit activity correlation."""

    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)  # e.g., CVE-2024-1234
    description = Column(Text)
    cvss_score = Column(Float)  # CVSS base score
    severity = Column(String(20))  # Critical, High, Medium, Low

    # Vendor and product info
    vendor = Column(String(200))
    product = Column(String(200))
    affected_versions = Column(ARRAY(String), default=list)

    # Dates
    published_date = Column(TIMESTAMP)
    last_modified = Column(TIMESTAMP)
    added_to_kev = Column(TIMESTAMP)  # When added to CISA KEV

    # Exploit information
    exploited_in_wild = Column(Boolean, default=False)
    exploit_available = Column(Boolean, default=False)
    ransomware_use = Column(Boolean, default=False)

    # MITRE ATT&CK mapping
    associated_techniques = Column(ARRAY(String), default=list)  # MITRE technique IDs

    # Remediation
    remediation_required = Column(Boolean, default=False)
    remediation_deadline = Column(TIMESTAMP)
    vendor_advisory = Column(Text)

    # Context and references
    context = Column(JSON)  # Additional metadata
    references = Column(ARRAY(String), default=list)  # URLs to advisories, PoCs, etc.
    tags = Column(ARRAY(String), default=list)

    # Tracking
    source = Column(String(100), default="cisa_kev")  # cisa_kev, nvd, etc.
    first_seen = Column(TIMESTAMP, default=datetime.utcnow)
    last_seen = Column(TIMESTAMP, default=datetime.utcnow)

    def __repr__(self):
        return f"<CVE(id={self.cve_id}, severity={self.severity}, exploited={self.exploited_in_wild})>"
