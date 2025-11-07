"""Initialize database with schema and seed data."""

import sys
import os
import asyncio

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.database import engine, SessionLocal, Base
from app.models import (
    ThreatIntel,
    MitreTechnique,
    DetectionTemplate,
    GeneratedQuery,
    HuntCampaign,
    CVE,
    ThreatActor,
    IOCEnrichment
)
from app.services.mitre_service import MitreAttackService
from app.services.query_generator import QueryGenerator
from app.templates import get_initial_templates


def init_database():
    """Create all database tables."""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ Database tables created")


def seed_templates():
    """Seed database with initial query templates."""
    print("\nSeeding initial query templates...")

    db = SessionLocal()
    try:
        generator = QueryGenerator(db)
        templates = get_initial_templates()

        count = 0
        for template_data in templates:
            technique_id, platform, query_template, variables, confidence, fp_notes, data_sources = template_data

            # Check if template already exists
            existing = db.query(DetectionTemplate).filter(
                DetectionTemplate.technique_id == technique_id,
                DetectionTemplate.platform == platform
            ).first()

            if existing:
                print(f"  - Template for {technique_id} on {platform} already exists, skipping")
                continue

            generator.add_template(
                technique_id=technique_id,
                platform=platform,
                query_template=query_template,
                variables=variables,
                confidence=confidence,
                false_positive_notes=fp_notes,
                data_sources_required=data_sources,
                created_by="system"
            )
            count += 1
            print(f"  ✓ Added template: {technique_id} ({platform})")

        print(f"✓ Seeded {count} query templates")

    finally:
        db.close()


async def download_mitre_data():
    """Download and populate MITRE ATT&CK data."""
    print("\nDownloading MITRE ATT&CK framework...")

    db = SessionLocal()
    try:
        service = MitreAttackService(db)
        count = await service.update_attack_data()
        print(f"✓ Downloaded and stored {count} MITRE ATT&CK techniques")

    except Exception as e:
        print(f"✗ Error downloading MITRE data: {e}")
        print("  You can run this later with: POST /api/techniques/update")

    finally:
        db.close()


def main():
    """Main initialization function."""
    print("=" * 60)
    print("Threat Hunt Generator - Database Initialization")
    print("=" * 60)

    # Initialize database schema
    init_database()

    # Seed templates
    seed_templates()

    # Download MITRE data
    print("\nWould you like to download MITRE ATT&CK data now?")
    print("(This requires internet connection and may take a minute)")
    response = input("Download MITRE data? [y/N]: ").strip().lower()

    if response in ["y", "yes"]:
        asyncio.run(download_mitre_data())
    else:
        print("\nSkipping MITRE data download.")
        print("You can download it later via the API: POST /api/techniques/update")

    print("\n" + "=" * 60)
    print("✓ Database initialization complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Configure your .env file (copy from .env.example)")
    print("2. Run the API server: uvicorn app.main:app --reload")
    print("3. Visit http://localhost:8000/docs for API documentation")
    print("\nOptional:")
    print("- Update threat intelligence feeds: POST /api/threat-intel/update")
    print("- Generate your first query: POST /api/queries/generate")


if __name__ == "__main__":
    main()
