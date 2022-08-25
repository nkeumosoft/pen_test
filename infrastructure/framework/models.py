from infrastructure.framework import db


class Website(db.Model):
    __tablename__ = "website"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(254), nullable=True)

    def __init__(self, name, url):
        self.name = name
        self.url = url
