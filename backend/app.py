from flask import Flask
from flask_cors import CORS
from database.database import db
from backend.config import Config
import backend.models  # Ensures all 8 models are registered with SQLAlchemy
from backend.routes.devices import devices_bp


app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for API routes
CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}})

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
        "service": "ARPShield Backend",
        "database": "connected",
        "architecture": "rule-based"
    }


if __name__ == "__main__":
    app.run(debug=True)