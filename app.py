import os
from datetime import datetime

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

# -------------------------------------------------
# Flask + DB setup
# -------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "acthp.db")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -------------------------------------------------
# Models
# -------------------------------------------------
class Hunt(db.Model):
    __tablename__ = "hunts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    query_str = db.Column(db.Text, nullable=False)
    datasource = db.Column(db.String(100), nullable=False, default="SIEM")
    severity = db.Column(db.String(20), nullable=False, default="medium")
    status = db.Column(db.String(20), nullable=False, default="open")
    tags = db.Column(db.String(300), nullable=True)
    ai_score = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "query_str": self.query_str,
            "datasource": self.datasource,
            "severity": self.severity,
            "status": self.status,
            "tags": self.tags.split(",") if self.tags else [],
            "ai_score": self.ai_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# -------------------------------------------------
# One-time DB init + seed
#   - DOES NOT delete the DB
#   - Seeds only if empty
# -------------------------------------------------
def init_db_with_seed():
    with app.app_context():
        db.create_all()

        # use db.session.query(...).count() to avoid Hunt.query conflict
        existing = db.session.query(Hunt).count()
        if existing > 0:
            return

        sample_hunts = [
            Hunt(
                name="Suspicious PowerShell Execution",
                query_str="process_name: powershell.exe AND commandline:*EncodedCommand*",
                datasource="EDR",
                severity="high",
                status="open",
                tags="windows,powershell,lateral-movement",
                ai_score=0.92,
            ),
            Hunt(
                name="Rare External Destination Country",
                query_str="dst_country NOT IN ('IN','US','GB','DE') AND bytes_out > 100000",
                datasource="NetFlow",
                severity="medium",
                status="open",
                tags="exfiltration,network",
                ai_score=0.78,
            ),
            Hunt(
                name="Impossible Travel Login",
                query_str="geo_impossible_travel:true AND login_success:true",
                datasource="Identity",
                severity="critical",
                status="investigating",
                tags="identity,cloud,account-takeover",
                ai_score=0.96,
            ),
            Hunt(
                name="Anonymous VPN + Admin Access",
                query_str="vpn_vendor:anonymous AND role:admin AND action:login",
                datasource="VPN",
                severity="high",
                status="closed",
                tags="vpn,admin,privilege",
                ai_score=0.88,
            ),
        ]

        db.session.add_all(sample_hunts)
        db.session.commit()
        print("[DB] Seeded example hunts.")


# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route("/")
def index():
    hunts = Hunt.query.order_by(Hunt.created_at.desc()).all()

    total_hunts = len(hunts)
    open_hunts = sum(1 for h in hunts if h.status == "open")
    closed_hunts = sum(1 for h in hunts if h.status == "closed")
    investigating_hunts = sum(1 for h in hunts if h.status == "investigating")

    # severity distribution
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for h in hunts:
        sev_counts[h.severity] = sev_counts.get(h.severity, 0) + 1

    hunts_json = [h.to_dict() for h in hunts]

    return render_template(
        "index.html",
        hunts=hunts,
        hunts_json=hunts_json,
        sev_counts=sev_counts,
        total_hunts=total_hunts,
        open_hunts=open_hunts,
        closed_hunts=closed_hunts,
        investigating_hunts=investigating_hunts,
    )


# -------------------------------------------------
# Main
# -------------------------------------------------
if __name__ == "__main__":
    init_db_with_seed()
    app.run(host="0.0.0.0", port=5000, debug=False)
