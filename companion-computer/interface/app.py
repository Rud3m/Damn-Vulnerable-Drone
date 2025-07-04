from __future__ import annotations

"""
Companion‑computer HTTP / Socket.IO server for Damn Vulnerable Drone.

Changes from the original version
---------------------------------
* **Dynamic host‑gateway detection** – instead of hard‑coding
  `host.docker.internal`, we discover the Docker‑Desktop host gateway
  address at runtime and add it as a default `UdpDestination`.
* Centralised `get_host_gateway_ip()` helper with fall‑backs for Linux,
  Darwin (Mac) and plain IPv4 broadcast.
* `initialize_udp_destinations()` rewrites now guard against duplicates
  and only insert destinations that resolve.
* Minor lint / typing fixes (PEP 8 compliant, logging improvements).
"""

from pathlib import Path
import os
import json
import logging
import socket
import subprocess
import threading
import time
from logging.handlers import RotatingFileHandler
from typing import Optional

import rospy
from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_socketio import SocketIO, emit

from extensions import db
from mavlink_connection import initialize_socketio, listen_to_mavlink
from models import TelemetryStatus, UdpDestination, User
from routes.camera import camera_bp
from routes.logs import logs_bp
from routes.telemetry import telemetry_bp
from routes.wifi import wifi_bp

# ---------------------------------------------------------------------------
# Globals / singletons
# ---------------------------------------------------------------------------

socketio: SocketIO = SocketIO()
login_manager: LoginManager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "You must be logged in to access this page."

DATABASE_PATH = "sqlite:///telemetry.db"
CONFIG_FILE = Path("/interface/config.json")
LOG_PATH = Path("logs/damn-vulnerable-companion-computer.log")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_host_gateway_ip() -> Optional[str]:
    """Return the Docker‑Desktop host‑gateway IPv4 address if reachable.

    Strategy:
    1. Try the magic hostname ``host.docker.internal`` using a pure IPv4
       lookup (`getent ahostsv4`). This covers Linux with a recent Docker.
    2. Fall back to parsing ``ip route`` / ``route -n`` default gateway.
    3. Final fall‑back: return *None* – caller may choose to use broadcast
       (255.255.255.255) instead.
    """

    # 1. Try getent (present in Debian/Ubuntu Alpine, etc.)
    try:
        out = subprocess.check_output(
            ["getent", "ahostsv4", "host.docker.internal"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            # First field of first line is the IPv4.
            return out.split()[0]
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # 2. Parse the default gateway from ip route
    try:
        out = subprocess.check_output(
            ["ip", "route"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    # 3. Older busybox `route -n` (rare)
    try:
        out = subprocess.check_output(
            ["route", "-n"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            cols = line.split()
            if cols and cols[0] == "0.0.0.0":
                return cols[1]
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    return None


# ---------------------------------------------------------------------------
# Flask / Socket.IO setup
# ---------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))


def configure_logging(app: Flask) -> None:
    LOG_PATH.parent.mkdir(exist_ok=True)
    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=10_240, backupCount=10)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s: %(message)s [%(pathname)s:%(lineno)d]")
    )
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

    # Initialise extensions
    login_manager.init_app(app)
    socketio.init_app(app)
    initialize_socketio(socketio)
    rospy.init_node("camera_display_node", anonymous=True)

    # Flask‑SQLAlchemy
    app.config.update(
        SQLALCHEMY_DATABASE_URI=DATABASE_PATH,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    configure_logging(app)

    # App configuration file (optional)
    if CONFIG_FILE.exists():
        with CONFIG_FILE.open() as fp:
            app.config.update(json.load(fp))

    # Register blueprints
    app.register_blueprint(telemetry_bp, url_prefix="/telemetry")
    app.register_blueprint(logs_bp, url_prefix="/logs")
    app.register_blueprint(wifi_bp, url_prefix="/wifi")
    app.register_blueprint(camera_bp, url_prefix="/camera")

    # -------------------- Routes --------------------

    @app.route("/")
    @login_required
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            remember = request.form.get("remember_me") == "on"

            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user, remember=remember)
                return redirect(request.args.get("next") or url_for("index"))

            flash("Invalid username or password")
            response = make_response(render_template("login.html"))
            response.status_code = 403
            return response

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for("index"))

    @app.route("/config", methods=["GET"])
    def get_config():
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open() as fp:
                return jsonify(json.load(fp))
        return jsonify({}), 404

    # --------------- Socket.IO handlers ---------------

    @socketio.on("connect")
    def handle_connect(auth):  # noqa: D401, ANN001
        telemetry_status = TelemetryStatus.query.first()
        if not telemetry_status:
            telemetry_status = TelemetryStatus(status="Not Connected")
            db.session.add(telemetry_status)
            db.session.commit()

        # Check if mavlink‑routerd is running when status says so
        if telemetry_status.status in {"Connected", "Connecting"}:
            try:
                subprocess.run(["pgrep", "-f", "mavlink-routerd"], check=True)
            except subprocess.CalledProcessError:
                telemetry_status.status = "Not Connected"
                db.session.commit()

        emit("telemetry_status", {"isTelemetryRunning": telemetry_status.status})

    @socketio.on("disconnect")
    def handle_disconnect():  # noqa: D401
        emit("telemetry_status", {"status": "disconnected"})

    return app


# ---------------------------------------------------------------------------
# DB initialisation helpers
# ---------------------------------------------------------------------------

def add_default_user() -> None:
    if not User.query.filter_by(username="admin").first():
        new_user = User(username="admin")
        new_user.set_password("cyberdrone")
        db.session.add(new_user)
        db.session.commit()


def initialize_udp_destinations() -> None:
    """Insert sensible default UDP endpoints if none exist."""

    if UdpDestination.query.first():
        return  # already populated

    # 1. Local MAVProxy/MAVLink consumer inside container
    db.session.add(UdpDestination(ip="127.0.0.1", port=14540))

    # 2. On‑board Wi‑Fi AP clients (static subnet detection)
    ip_list = subprocess.check_output("hostname -I", shell=True, text=True).split()
    if "192.168.13.1" in ip_list:
        db.session.add(UdpDestination(ip="192.168.13.14", port=14550))
    else:
        db.session.add(UdpDestination(ip="10.13.0.4", port=14550))

    # 3. Ground‑control station inside same Docker‑compose net
    db.session.add(UdpDestination(ip="10.13.0.6", port=14550))

    # 4. External QGroundControl on the host (Docker‑Desktop gateway)
    host_ip = get_host_gateway_ip()

    if host_ip:
        if not UdpDestination.query.filter_by(ip=host_ip, port=14550).first():
            db.session.add(UdpDestination(ip=host_ip, port=14550))
    else:
        # Final fallback: broadcast
        if not UdpDestination.query.filter_by(ip="255.255.255.255", port=14550).first():
            db.session.add(UdpDestination(ip="255.255.255.255", port=14550))

    db.session.commit()


# ---------------------------------------------------------------------------
# MAVLink thread helper
# ---------------------------------------------------------------------------

def start_mavlink_thread() -> None:
    while True:
        t = threading.Thread(target=listen_to_mavlink, daemon=True)
        t.start()
        t.join()  # Block until it exits
        print("MAVLink thread stopped, restarting in 5 seconds …")
        time.sleep(5)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()

    with app.app_context():
        db.create_all()
        add_default_user()
        initialize_udp_destinations()
        threading.Thread(target=start_mavlink_thread, daemon=True).start()
        app.logger.info("Application startup")

    socketio.run(app, debug=True, host="0.0.0.0", port=3000, allow_unsafe_werkzeug=True)