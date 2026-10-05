from flask import Flask, render_template
from flask_cors import CORS
from database.database import db
from backend.config import Config
import backend.models  # Ensures all 8 models are registered with SQLAlchemy
from backend.routes.devices import devices_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.alerts import alerts_bp
from backend.routes.incidents import incidents_bp
from backend.routes.impact import impact_bp
from backend.routes.mitigation import mitigation_bp
from backend.routes.recovery import recovery_bp
from backend.routes.arp import arp_bp


app = Flask(__name__, template_folder="../dashboard/templates", static_folder="../dashboard/static")
app.config.from_object(Config)

# Enable CORS for API routes
CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}})

# Connect the database to Flask
db.init_app(app)
app.register_blueprint(devices_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(impact_bp)
app.register_blueprint(mitigation_bp)
app.register_blueprint(recovery_bp)
app.register_blueprint(arp_bp)


# Create database tables
with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return render_template("overview.html")

@app.route("/devices")
def devices_page():
    return render_template("devices.html")

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")

@app.route("/incidents")
def incidents_page():
    return render_template("incidents.html")

@app.route("/impact")
def impact_page():
    return render_template("impact.html")

@app.route("/mitigation")
def mitigation_page():
    return render_template("mitigation.html")

@app.route("/recovery")
def recovery_page():
    return render_template("recovery.html")

@app.route("/arp")
def arp_traffic_page():
    return render_template("arp.html")

@app.route("/api/health")
def health():
    return {
        "status": "ok",
        "service": "ARPShield Backend",
        "database": "connected",
        "architecture": "rule-based"
    }


if __name__ == "__main__":
    app.run(debug=True)