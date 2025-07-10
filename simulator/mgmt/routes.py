from flask import Blueprint, render_template, url_for, redirect, make_response, abort
import docker
from docker.errors import NotFound
from models import Stage
from extensions import db
from models import Stage
import logging
import json
import requests
import threading
import os
import yaml
import re


logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

main = Blueprint('main', __name__)


def send_start_telemetry_request(data):
    url = 'http://10.13.0.3:3000/telemetry/start-telemetry'
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, data=json.dumps(data), headers=headers)
        logging.info("Telemetry response: %s", response.text)
    except requests.exceptions.RequestException as e:
        logging.error("Failed to send telemetry data: %s", str(e))

def send_stop_telemetry_request():
    url = 'http://10.13.0.3:3000/telemetry/stop-telemetry'
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, headers=headers)
        logging.info("Telemetry response: %s", response.text)
    except requests.exceptions.RequestException as e:
        logging.error("Failed to send telemetry data: %s", str(e))

@main.route("/qgc", methods=["POST"])
def open_qgc():
    client = docker.from_env()
    container_name = "ground-control-station"
    script_path = "/usr/local/bin/launch_qgc.sh"

    try:
        container = client.containers.get(container_name)
        if container.status != "running":
            return make_response(
                f"Container {container_name} is not running (status: {container.status})",
                400,
            )

        # make sure the script exists & is executable (still as root)
        for test_cmd, error_txt in [
            (f'test -f "{script_path}"', "Script not found"),
            (f'test -x "{script_path}"', "Script is not executable"),
        ]:
            rc, _ = container.exec_run(test_cmd)
            if rc != 0:
                return make_response(f"{error_txt}: {script_path}", 400)

        exec_result = container.exec_run(script_path, user="gcs")
        output = exec_result.output.decode(errors="ignore").strip()

        if exec_result.exit_code == 0:
            return make_response(f"Success:\n{output}", 200)
        else:
            return make_response(
                f"Command failed with exit code {exec_result.exit_code}:\n{output}",
                400,
            )

    except docker.errors.NotFound:
        return make_response(f"Container not found: {container_name}", 400)
    except Exception as e:
        return make_response(f"Unexpected error: {str(e)}", 500)

@main.route('/')
def index():
    stages = Stage.query.all()
    return render_template('pages/simulator.html', stages=stages, current_page='home')

@main.route('/reset', methods=['POST'])
def reset_world():
    print('Resetting World Simulation...')
    stage1 = Stage.query.filter_by(name='Stage 1').first()
    stage1.status = 'Enabled'
    stage2 = Stage.query.filter_by(name='Stage 2').first()
    stage2.status = 'Disabled'
    stage3 = Stage.query.filter_by(name='Stage 3').first()
    stage3.status = 'Disabled'
    stage4 = Stage.query.filter_by(name='Stage 4').first()
    stage4.status = 'Disabled'
    stage5 = Stage.query.filter_by(name='Stage 5').first()
    stage5.status = 'Disabled'
    stage6 = Stage.query.filter_by(name='Stage 6').first()
    stage6.status = 'Disabled'
    db.session.commit()

    # Reset Flight Controller
    ########################################################
    client = docker.from_env()
    container = client.containers.get('flight-controller')
    kill_command_1 = "pkill -f sim_vehicle.py"
    container.exec_run(kill_command_1)
    kill_command_2 = "pkill -f arducopter"
    container.exec_run(kill_command_2)

    # Remove all MAVLink logs from the flight controller
    container.exec_run(cmd="sh -c 'rm -rf /ardupilot/logs/*'", workdir="/")

    # Stop telemetry on the companion computer
    send_stop_telemetry_request()

    output = 'Reset'
    return render_template('pages/simulator.html', output=output, current_page='home')


@main.route('/stage1', methods=['POST', ])
def stage1():
    """
    Stage 1: Initial Boot
    """
    stage1 = Stage.query.filter_by(name='Stage 1').first()
    stage2 = Stage.query.filter_by(name='Stage 2').first()
    stage1.status = 'Active'
    stage2.status = 'Enabled'
    db.session.commit()


    # Start up the Flight Controller
    client = docker.from_env()
    container = client.containers.get('flight-controller')
    logging.info('Triggering Stage 1...')
    command = "Tools/autotest/sim_vehicle.py -v ArduCopter --add-param-file drone.parm --custom-location 37.241861,-115.796917,137,340 -f gazebo-iris --no-rebuild --no-mavproxy --sim-address=10.13.0.5 -A '--serial0=uart:/dev/ttyACM0:57600'"
    
    # Log the command before executing it
    logging.info("Executing command: %s", command)

    # Execute the command and capture the output in real-time
    output_stream = []
    for line in container.exec_run(command, stream=True):
        if isinstance(line, bytes):
            line = line.decode()
        logging.info("Command output: %s", line)
        output_stream.append(line)

    # Start up the Companion Computer Telemetry
    logging.info('Starting MAVLink Router on Companion Computer...')

    # POST request to start telemetry
    data = {
        'serial_device': '/dev/ttyUSB0',
        'baud_rate': '57600',
        'mavlink_version': '2',
        'enable_udp_server': False,
        'udp_server_port': '14550',
        'enable_tcp_server': True,
        'enable_datastream_requests': False,
        'enable_heartbeat': False,
        'enable_tlogs': False
    }

    # Send request but don't wait for response
    thread = threading.Thread(target=send_start_telemetry_request, args=(data,))
    thread.start()

    # response = requests.post('http://localhost:3000/telemetry/start-telemetry', data=json.dumps(data))
    # logging.info("Telemetry response: %s", response.text)

    return render_template('pages/simulator.html', output=output_stream, current_page='home')

@main.route('/stage2', methods=['POST', ])
def stage2():
    """
    Stage 2: Arm & Takeoff
    """
    stage2 = Stage.query.filter_by(name='Stage 2').first()
    stage3 = Stage.query.filter_by(name='Stage 3').first()
    stage2.status = 'Active'
    stage3.status = 'Enabled'
    db.session.commit()

    client = docker.from_env()
    container = client.containers.get('ground-control-station')
    logging.info('Triggering Stage 2...')
    command = "python3 /arm-and-takeoff.py"
    
    # Log the command before executing it
    logging.info("Executing command: %s", command)

    # Execute the command and capture the output in real-time
    try:
        exit_code, output = container.exec_run(command, stream=False)
        output = output.decode() if isinstance(output, bytes) else output
        logging.info("Command output: %s", output)
    except Exception as e:
        logging.error("Container execution error: %s", str(e))
        output = str(e)
    
    return render_template('pages/simulator.html', output=output, current_page='home')


@main.route('/stage3', methods=['POST', ])
def stage3():
    """
    Stage 3: Autopilot Flight
    """
    stage3 = Stage.query.filter_by(name='Stage 3').first()
    stage4 = Stage.query.filter_by(name='Stage 4').first()
    stage3.status = 'Active'
    stage4.status = 'Enabled'
    db.session.commit()

    client = docker.from_env()
    container = client.containers.get('ground-control-station')
    logging.info('Triggering Stage 3...')
    command = "python3 /autopilot-flight.py"
    
    # Log the command before executing it
    logging.info("Executing command: %s", command)

    # Execute the command and capture the output in real-time
    try:
        exit_code, output = container.exec_run(command, stream=False)
        output = output.decode() if isinstance(output, bytes) else output
        logging.info("Command output: %s", output)
    except Exception as e:
        logging.error("Container execution error: %s", str(e))
        output = str(e)
    
    return render_template('pages/simulator.html', output=output, current_page='home')

@main.route('/stage4', methods=['POST', ])
def stage4():
    """
    Stage 4: Return to Land
    """
    stage4 = Stage.query.filter_by(name='Stage 4').first()
    stage5 = Stage.query.filter_by(name='Stage 5').first()
    stage4.status = 'Active'
    stage5.status = 'Enabled'
    db.session.commit()

    client = docker.from_env()
    container = client.containers.get('ground-control-station')
    logging.info('Triggering Stage 4...')
    command = "python3 /return-to-land.py"
    
    # Log the command before executing it
    logging.info("Executing command: %s", command)

    # Execute the command and capture the output in real-time
    try:
        exit_code, output = container.exec_run(command, stream=False)
        output = output.decode() if isinstance(output, bytes) else output
        logging.info("Command output: %s", output)
    except Exception as e:
        logging.error("Container execution error: %s", str(e))
        output = str(e)
    
    return render_template('pages/simulator.html', output=output, current_page='home')

@main.route('/stage5', methods=['POST', ])
def stage5():
    """
    Stage 5: Post Flight Analysis
    """
    stage5 = Stage.query.filter_by(name='Stage 5').first()
    stage5.status = 'Active'
    db.session.commit()

    client = docker.from_env()
    container = client.containers.get('ground-control-station')
    logging.info('Triggering Stage 5...')
    command = "python3 /post-flight-analysis.py"

    stage1 = Stage.query.filter_by(name='Stage 1').first()
    stage1.status = 'Enabled'
    stage2 = Stage.query.filter_by(name='Stage 2').first()
    stage2.status = 'Disabled'
    stage3 = Stage.query.filter_by(name='Stage 3').first()
    stage3.status = 'Disabled'
    stage4 = Stage.query.filter_by(name='Stage 4').first()
    stage4.status = 'Disabled'
    stage5 = Stage.query.filter_by(name='Stage 5').first()
    stage5.status = 'Disabled'
    stage6 = Stage.query.filter_by(name='Stage 6').first()
    stage6.status = 'Disabled'
    db.session.commit()
    
    # Log the command before executing it
    logging.info("Executing command: %s", command)

    # Execute the command and capture the output in real-time
    try:
        exit_code, output = container.exec_run(command, stream=False)
        output = output.decode() if isinstance(output, bytes) else output
        logging.info("Command output: %s", output)
    except Exception as e:
        logging.error("Container execution error: %s", str(e))
        output = str(e)
    
    return render_template('pages/simulator.html', output=output, current_page='home')


###############################
# Getting Started
###############################
@main.route('/getting-started')
def getting_started():
    return render_template('pages/getting-started.html', section=None, current_page='getting-started')

###############################
# Simulation Guide
###############################

@main.route('/guide/')
def guide_index():
    return render_template('pages/guide/index.html', section='guide')

@main.route('/guide/basic-operations')
def guide_basics():
    return render_template('pages/guide/basic-operations.html', section='guide', current_page='basic-operations')

@main.route('/guide/system-architecture')
def guide_ui():
    return render_template('pages/guide/system-architecture.html', section='guide', current_page='system-architecture')

@main.route('/guide/system-health-check')
def guide_health():
    return render_template('pages/guide/system-health-check.html', section='guide', current_page='system-health-check')

@main.route('/guide/manual-testing')
def guide_manual_testing():
    return render_template('pages/guide/manual-testing.html', section='guide', current_page='manual-testing')

@main.route('/guide/troubleshooting')
def guide_troubleshooting():
    return render_template('pages/guide/troubleshooting.html', section='guide', current_page='troubleshooting')


###############################
# Learning Resouces
###############################

@main.route('/learning/')
def learning_index():
    return render_template('pages/learning/index.html', section='learning')

@main.route('/learning/aircrack-ng')
def learning_aircrackng():
    return render_template('pages/learning/aircrack-ng.html', section='learning', current_page='aircrack-ng')

@main.route('/learning/wireshark')
def learning_wireshark():
    return render_template('pages/learning/wireshark.html', section='learning', current_page='wireshark')

@main.route('/learning/mavlink')
def learning_mavlink():
    return render_template('pages/learning/mavlink.html', section='learning', current_page='mavlink')

@main.route('/learning/mavproxy')
def learning_mavproxy():
    return render_template('pages/learning/mavproxy.html', section='learning', current_page='mavproxy')

@main.route('/learning/ardupilot')
def learning_ardupilot():
    return render_template('pages/learning/ardupilot.html', section='learning', current_page='ardupilot')

@main.route('/learning/arducopter')
def learning_arducopter():
    return render_template('pages/learning/arducopter.html', section='learning', current_page='arducopter')

@main.route('/learning/sitl')
def learning_sitl():
    return render_template('pages/learning/sitl.html', section='learning', current_page='sitl')

@main.route('/learning/gazebo')
def learning_gazebo():
    return render_template('pages/learning/gazebo.html', section='learning', current_page='gazebo')

@main.route('/learning/swarmsec')
def learning_swarmsec():
    return render_template('pages/learning/swarmsec.html', section='learning', current_page='swarmsec')


###############################
# Attack Scenarios & Solutions
###############################
@main.route('/attacks/all')
@main.route('/attacks')
def attacks_index():
    base_dir = 'templates/pages/attacks'
    categories = {
        'Reconnaissance': load_yaml_files(os.path.join(base_dir, 'recon')),
        'Protocol Tampering': load_yaml_files(os.path.join(base_dir, 'tampering')),
        'Denial of Service': load_yaml_files(os.path.join(base_dir, 'dos')),
        'Injection': load_yaml_files(os.path.join(base_dir, 'injection')),
        'Exfiltration': load_yaml_files(os.path.join(base_dir, 'exfiltration')),
        'Firmware Attacks': load_yaml_files(os.path.join(base_dir, 'firmware')),
    }
    return render_template('pages/attacks/list.html', section='attacks', sub_section='', current_page='attacks', categories=categories)

def load_yaml_files(directory):
    attacks = []
    
    # List and load files
    for filename in os.listdir(directory):
        if filename.endswith('.yaml'):
            with open(os.path.join(directory, filename), 'r') as file:
                yaml_content = yaml.safe_load(file)
                # Read the order number
                order = yaml_content.get('order', float('inf'))
                # Append the file content and order number
                attacks.append({
                    'order': order,
                    'title': yaml_content.get('title', 'No Title'),
                    'link': f"/attacks/{os.path.basename(directory)}/{filename.replace('.yaml', '')}"
                })
    
    # Sort the attacks list by the order number
    attacks.sort(key=lambda x: x['order'])
    
    return attacks

def convert_code_blocks(text):
    if isinstance(text, str):
        # Replace triple backticks with <pre><code> to preserve new lines
        text = re.sub(r'```(.*?)```', r'<pre><code class="code mb-3 mt-3">\1</code></pre>', text, flags=re.DOTALL)
        # Replace single backticks with <code> for inline code
        text = re.sub(r'(?<!`)`([^`]+)`(?!`)', r'<code>\1</code>', text)
    return text

SLUG_OVERRIDES = {}

def slugify(title: str) -> str:
    """
    Convert a human-readable title into a GitHub-Wiki-friendly slug.

    * Spaces/underscores → dash
    * Keep A-Z, a-z, 0-9, dash, &
    * Strip everything else
    * Collapse multiple dashes
    """
    s = title.strip()
    s = re.sub(r"[ _]+", "-", s)          # spaces/underscores → -
    s = re.sub(r"[^A-Za-z0-9\-\&]", "", s)  # drop symbols except dash & &
    s = re.sub(r"-{2,}", "-", s)          # -- → -
    return s


@main.route("/attacks/<tactic>/<filename>")
def redirect_attack_scenario(tactic: str, filename: str):
    """
    Example:
        /attacks/navigation/altitude-spoofing  →
        https://github.com/nicholasaleks/Damn-Vulnerable-Drone/wiki/Altitude-Spoofing
    """
    # ── Locate & load the YAML file ─────────────────────────────
    base_name = filename.rsplit(".", 1)[0]          # strip .yaml if present
    yaml_path = os.path.join(
        "templates", "pages", "attacks", tactic, f"{base_name}.yaml"
    )

    if not os.path.exists(yaml_path):
        abort(404)

    with open(yaml_path, "r", encoding="utf-8") as f:
        yaml_content = yaml.safe_load(f) or {}

    title = yaml_content.get("title", base_name)

    # ── Build the Wiki slug ────────────────────────────────────
    wiki_slug = SLUG_OVERRIDES.get(title, slugify(title))

    wiki_url = (
        f"https://github.com/nicholasaleks/Damn-Vulnerable-Drone/wiki/{wiki_slug}"
    )

    # ── Redirect the user ──────────────────────────────────────
    return redirect(wiki_url, code=302)

###############################
# Errors
###############################

@main.errorhandler(404)
def page_not_found(e):
    return render_template('pages/errors/404.html'), 404
