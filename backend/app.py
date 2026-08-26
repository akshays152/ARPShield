from flask import Flask
from database.database import db
from backend.models.device import Device
from backend.routes.devices import devices_bp


app = Flask(__name__)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///arpshield.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Connect the database to Flask
db.init_app(app)
app.register_blueprint(devices_bp)

# Create database tables
with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return "ARPShield Backend is running."


@app.route("/api/health")
def health():
    return {
        "status": "ok",
        "service": "ARPShield Backend"
    }


if __name__ == "__main__":
    app.run(debug=True)