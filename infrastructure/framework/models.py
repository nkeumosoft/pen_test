import uuid
from datetime import datetime

from infrastructure.framework import db
from sqlalchemy.dialects.postgresql import UUID


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
    website_id = db.Column(UUID(as_uuid=True), db.ForeignKey('website.id'))
    attack_name = db.Column(db.String(254), nullable=False)
    num_vulnerability = db.Column(db.Integer, default=0)
    attack_details = db.Column(db.JSON, nullable=False, default={})
    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __int__(self, website_id, attack_name, num_vulnerability, attack_details):
        self.attack_name = attack_name
        self.num_vulnerability = num_vulnerability
        self.attack_details = attack_details
        self.website_id = website_id


class PentestAnomalies(db.Model):
    __tablename__ = 'anomalies'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id = db.Column(UUID(as_uuid=True), db.ForeignKey('website.id'))
    name = db.Column(db.String(254), nullable=False)
    number = db.Column(db.Integer, default=0)
    details = db.Column(db.JSON, nullable=False, default={})
    created_date = db.Column(db.DateTime, default=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

    def __int__(self, website_id, name, number, details):
        self.website_id = website_id
        self.name = name
        self.number = number
        self.details = details