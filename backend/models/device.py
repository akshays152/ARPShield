from database.database import db


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(db.String(45), nullable=False, unique=True)
    mac_address = db.Column(db.String(17), nullable=False)

    hostname = db.Column(db.String(255), nullable=True)
    device_type = db.Column(db.String(100), nullable=True)

    status = db.Column(db.String(20), nullable=False, default="unknown")

    trusted = db.Column(db.Boolean, nullable=False, default=False)

    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)