"""Target Knowledge Model & Attack Surface Manager (Doc 03, Doc 11 & Doc 15).

Builds and queries the structured relational model of discovered targets:
Asset -> Host -> Service -> Application -> Endpoint
"""

from typing import Dict, List, Optional, Any
from sqlmodel import select, Session

from ..storage.database import DatabaseManager
from ..models.entities import Asset, Host, Service, Application, Endpoint
from ..models.enums import AssetType, ConfidenceLevel
from ..recon.normalizer import AssetNormalizer


class TargetModelManager:
    """Manages the attack surface graph within an engagement's isolated database."""

    def __init__(self, db_manager: DatabaseManager, engagement_id: str):
        self.db_manager = db_manager
        self.engagement_id = engagement_id

    def add_asset(
        self,
        asset_type: AssetType,
        value: str,
        source: str,
        parent_id: Optional[str] = None,
        in_scope: bool = True
    ) -> Asset:
        """Add and deduplicate an asset."""
        norm_val = AssetNormalizer.normalize_domain(value) if asset_type in {AssetType.DOMAIN, AssetType.SUBDOMAIN} else value.strip()
        
        with self.db_manager.get_session(self.engagement_id) as session:
            # Check existing
            stmt = select(Asset).where(
                Asset.engagement_id == self.engagement_id,
                Asset.value == norm_val
            )
            existing = session.exec(stmt).first()
            if existing:
                return existing

            asset = Asset(
                engagement_id=self.engagement_id,
                asset_type=asset_type,
                value=norm_val,
                parent_id=parent_id,
                discovery_source=source,
                in_scope=in_scope,
                confidence=ConfidenceLevel.CONFIRMED
            )
            session.add(asset)
            session.commit()
            session.refresh(asset)
            return asset

    def add_host(self, asset_id: str, hostname: str, ip_addresses: List[str]) -> Host:
        """Link network host metadata to an asset."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Host).where(
                Host.engagement_id == self.engagement_id,
                Host.hostname == hostname
            )
            existing = session.exec(stmt).first()
            if existing:
                # Update IPs
                merged_ips = list(set(existing.ip_addresses + ip_addresses))
                existing.ip_addresses = merged_ips
                session.add(existing)
                session.commit()
                session.refresh(existing)
                return existing

            host = Host(
                engagement_id=self.engagement_id,
                asset_id=asset_id,
                hostname=hostname,
                ip_addresses=ip_addresses
            )
            session.add(host)
            session.commit()
            session.refresh(host)
            return host

    def add_service(self, host_id: str, port: int, protocol: str, service_name: str) -> Service:
        """Record an exposed service on a host."""
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Service).where(
                Service.engagement_id == self.engagement_id,
                Service.host_id == host_id,
                Service.port == port,
                Service.protocol == protocol
            )
            existing = session.exec(stmt).first()
            if existing:
                return existing

            service = Service(
                engagement_id=self.engagement_id,
                host_id=host_id,
                port=port,
                protocol=protocol,
                service_name=service_name
            )
            session.add(service)
            session.commit()
            session.refresh(service)
            return service

    def add_application(self, name: str, base_url: str, technologies: List[str]) -> Application:
        """Record an identified web application and detected technologies."""
        norm_url = AssetNormalizer.normalize_url(base_url)
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Application).where(
                Application.engagement_id == self.engagement_id,
                Application.base_url == norm_url
            )
            existing = session.exec(stmt).first()
            if existing:
                # Merge technologies
                merged_tech = list(set(existing.technologies + technologies))
                existing.technologies = merged_tech
                session.add(existing)
                session.commit()
                session.refresh(existing)
                return existing

            app = Application(
                engagement_id=self.engagement_id,
                name=name,
                base_url=norm_url,
                technologies=technologies
            )
            session.add(app)
            session.commit()
            session.refresh(app)
            return app

    def add_endpoint(self, application_id: str, method: str, path: str) -> Endpoint:
        """Record a discovered application interaction point."""
        norm_path = AssetNormalizer.normalize_endpoint_path(path)
        method_clean = method.strip().upper()
        
        with self.db_manager.get_session(self.engagement_id) as session:
            stmt = select(Endpoint).where(
                Endpoint.engagement_id == self.engagement_id,
                Endpoint.application_id == application_id,
                Endpoint.method == method_clean,
                Endpoint.path == norm_path
            )
            existing = session.exec(stmt).first()
            if existing:
                return existing

            endpoint = Endpoint(
                engagement_id=self.engagement_id,
                application_id=application_id,
                method=method_clean,
                path=norm_path
            )
            session.add(endpoint)
            session.commit()
            session.refresh(endpoint)
            return endpoint

    def get_summary(self) -> Dict[str, int]:
        """Return attack surface metrics."""
        with self.db_manager.get_session(self.engagement_id) as session:
            assets_count = len(session.exec(select(Asset).where(Asset.engagement_id == self.engagement_id)).all())
            hosts_count = len(session.exec(select(Host).where(Host.engagement_id == self.engagement_id)).all())
            services_count = len(session.exec(select(Service).where(Service.engagement_id == self.engagement_id)).all())
            apps_count = len(session.exec(select(Application).where(Application.engagement_id == self.engagement_id)).all())
            endpoints_count = len(session.exec(select(Endpoint).where(Endpoint.engagement_id == self.engagement_id)).all())

            return {
                "assets": assets_count,
                "hosts": hosts_count,
                "services": services_count,
                "applications": apps_count,
                "endpoints": endpoints_count
            }

    def get_applications(self) -> List[Application]:
        """Retrieve all discovered applications."""
        with self.db_manager.get_session(self.engagement_id) as session:
            return session.exec(select(Application).where(Application.engagement_id == self.engagement_id)).all()

    def get_endpoints(self) -> List[Endpoint]:
        """Retrieve all discovered endpoints."""
        with self.db_manager.get_session(self.engagement_id) as session:
            return session.exec(select(Endpoint).where(Endpoint.engagement_id == self.engagement_id)).all()

    def get_hierarchy(self) -> List[Dict[str, Any]]:
        """Get structured hierarchical attack surface tree."""
        with self.db_manager.get_session(self.engagement_id) as session:
            hosts = session.exec(select(Host).where(Host.engagement_id == self.engagement_id)).all()
            apps = session.exec(select(Application).where(Application.engagement_id == self.engagement_id)).all()
            services = session.exec(select(Service).where(Service.engagement_id == self.engagement_id)).all()
            endpoints = session.exec(select(Endpoint).where(Endpoint.engagement_id == self.engagement_id)).all()

            tree = []
            for h in hosts:
                h_services = [s for s in services if s.host_id == h.id]
                h_apps = [a for a in apps if h.hostname in a.base_url]
                tree.append({
                    "hostname": h.hostname,
                    "ips": h.ip_addresses,
                    "services": [{"port": s.port, "protocol": s.protocol, "name": s.service_name} for s in h_services],
                    "applications": [
                        {
                            "base_url": a.base_url,
                            "technologies": a.technologies,
                            "endpoints": [{"method": e.method, "path": e.path} for e in endpoints if e.application_id == a.id]
                        }
                        for a in h_apps
                    ]
                })
            return tree
