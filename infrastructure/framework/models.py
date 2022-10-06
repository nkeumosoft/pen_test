import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from infrastructure.framework import db


class Website(db.Model):
    __tablename__ = "website"

    id = db.Column(UUID(as_uuid=True), primary_key=True)
    name = db.Column(db.String(50), nullable=True)
    url = db.Column(db.String(254), nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __init__(self, id, name, url):
        self.id = id
        self.name = name
        self.url = url



class PenTestVulnerability(db.Model):
    __tablename__ = 'Vulnerability'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id = db.Column(UUID(as_uuid=True), db.ForeignKey('website.id'), index=True, nullable=False)

    attack_name = db.Column(db.String(254), nullable=False)

    num_vulnerability = db.Column(db.Integer, default=0)
    attack_details = db.Column(db.JSON, nullable=False, default={})
    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __init__(self, website_id, attack_name, num_vulnerability, attack_details):
        self.attack_name = attack_name
        self.num_vulnerability = num_vulnerability
        self.attack_details = attack_details
        self.website_id = website_id


class PentestAnomalies(db.Model):
    __tablename__ = 'anomalies'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id = db.Column(UUID(as_uuid=True), db.ForeignKey('website.id'), index=True, nullable=False)
    name = db.Column(db.String(254), nullable=False)
    number = db.Column(db.Integer, default=0)
    details = db.Column(db.JSON, nullable=False, default={})
    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __init__(self, website_id, name, number, details):
        self.website_id = website_id
        self.name = name
        self.number = number
        self.details = details


class NmapScanInfo(db.Model):
    __tablename__ = 'nmap_scan_info'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id = db.Column(UUID(as_uuid=True), db.ForeignKey('website.id'), index=True, nullable=False)
    ports = db.Column(db.String(25), nullable=True)
    arguments = db.Column(db.String(255), nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __init__(self, id, website_id,  arguments: str, ports: str):
        self.id = id
        self.website_id = website_id
        self.arguments = arguments
        self.ports = ports


class NmapResult(db.Model):
    __tablename__ = 'nmap_result'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = db.Column(UUID(as_uuid=True), db.ForeignKey('nmap_scan_info.id'), index=True, nullable=False)
    # hostname_type = db.Column(db.String(25), nullable=True)
    protocol = db.Column(db.String(25), nullable=True)
    # host_ip = db.Column(db.String(255), nullable=True)
    port = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(255), nullable=True)
    state = db.Column(db.String(255), nullable=True)
    product = db.Column(db.String(255), nullable=True)
    extra_info = db.Column(db.String(255), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    version = db.Column(db.String(255), nullable=True)
    conf = db.Column(db.String(255), nullable=True)
    cpe = db.Column(db.String(255), nullable=True)

    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __init__(self,
                 scan_id,
                 protocol: str,
                 port: str,
                 name: str,
                 state: str,
                 product: str,
                 extra_info: str,
                 reason: str,
                 version: str,
                 conf: str, cpe):
        self.scan_id = scan_id
        self.protocol = protocol
        self.port = port
        self.name = name
        self.state = state
        self.product = product
        self.extra_info = extra_info
        self.reason = reason
        self.version = version
        self.conf = conf
        self.cpe = cpe
