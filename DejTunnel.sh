#!/bin/bash

set -e

# --- Global Configuration ---
PROJECT_DIR="/var/www/tinc_panel"
VENV_DIR="$PROJECT_DIR/venv"
INTERNAL_PORT="8001" # Internal port for Gunicorn

# --- Menu and UI Functions ---
print_menu() {
    clear
    echo -e "\033[1;36m┌──────────────────────────────────────────────────────────────────┐\033[0m"
    echo -e "\033[1;36m│\033[0m                                                                  \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m███████╗██╗   ██╗██╗      █████╗ ███╗   ██╗\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m██╔════╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m█████╗   ╚████╔╝ ██║     ███████║██╔██╗ ██║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m██╔══╝    ╚██╔╝  ██║     ██╔══██║██║╚██╗██║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m███████╗   ██║   ███████╗██║  ██║██║ ╚████║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m                                                                  \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m█████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗\033[0m             \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║\033[0m              \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║\033[0m              \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║\033[0m              \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗\033[0m         \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝\033[0m         \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m                                                                  \033[1;36m│\033[0m"
    echo -e "\033[1;36m└──────────────────────────────────────────────────────────────────┘\033[0m"

    if [ -d "$PROJECT_DIR" ]; then
        echo -e "\n  \033[1;32m1)\033[0m Reinstall DejTunnel"
        echo -e "  \033[1;31m2)\033[0m Complete Uninstall"
        echo -e "  \033[1;34m3)\033[0m Change Username / Password / Port"
        echo -e "  \033[1;33m4)\033[0m Exit\n"
    else
        echo -e "\n  \033[1;32m1)\033[0m Install DejTunnel"
        echo -e "  \033[1;33m2)\033[0m Exit\n"
    fi
}

wait_for_enter() {
    echo -e "\n\033[1;33mPress [Enter] to return to the main menu...\033[0m"
    read
}

# --- Core Logic Functions ---
run_full_uninstall() {
    echo -e "\033[0;31m\n--- Starting Complete Uninstallation ---\033[0m"
    read -p "WARNING: This will permanently remove DejTunnel, all Tinc configurations, and the database. Are you sure? [y/N]: " confirmation
    if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
        echo -e "\033[1;33mUninstall cancelled.\033[0m"
        return
    fi

    echo "  -> Stopping services..."
    systemctl stop tinc_panel nginx tinc@* &>/dev/null || true

    echo "  -> Removing system files..."
    rm -rf "$PROJECT_DIR" \
           /etc/tinc \
           /etc/systemd/system/tinc_panel.service \
           /etc/nginx/sites-available/tinc_panel \
           /etc/nginx/sites-enabled/tinc_panel

    echo "  -> Reloading system services..."
    systemctl daemon-reload
    echo -e "\033[1;32mUninstallation has been completed successfully.\033[0m"
}

change_configuration() {
    echo -e "\033[1;34m\n--- Change DejTunnel Configuration ---\033[0m"
    read -p "Enter new web panel port (leave blank to keep current): " NEW_PORT
    if [[ -n "$NEW_PORT" ]]; then
        echo "  -> Changing port..."
        OLD_PORT=$(grep -E '^\s*listen\s+' /etc/nginx/sites-available/tinc_panel | awk '{print $2}' | sed 's/;//')
        if [[ -n "$OLD_PORT" ]]; then
            sed -i "s/listen ${OLD_PORT};/listen ${NEW_PORT};/" /etc/nginx/sites-available/tinc_panel
            systemctl restart nginx
            echo -e "\033[1;32m  -> Port successfully changed to ${NEW_PORT}.\033[0m"
        else
            echo -e "\033[1;31m  -> Could not determine the old port. Port not changed.\033[0m"
        fi
    fi

    read -p "Enter new admin username (leave blank to keep current): " NEW_USER
    read -s -p "Enter new admin password (leave blank to keep current): " NEW_PASS; echo
    if [[ -n "$NEW_USER" || -n "$NEW_PASS" ]]; then
        echo "  -> Updating credentials in database..."
        CMD_OUTPUT=$(bash -c "cd $PROJECT_DIR && source venv/bin/activate && python3 update_credentials.py '$NEW_USER' '$NEW_PASS' 2>&1")
        echo -e "\033[0;35m  -> Script output: ${CMD_OUTPUT}\033[0m"
    fi
    echo -e "\n\033[1;32mConfiguration update finished.\033[0m"
}

run_installation() {
    echo -e "\033[1;32m\n--- Starting DejTunnel Panel Installation\033[0m"

    # --- PART 1: GATHER ALL INFORMATION ---
    echo -e "\n\033[1;34mStep 1/7: Gathering Configuration Details\033[0m"
    read -p "Enter this server's public IP address: " SERVER_PUBLIC_IP
    read -p "Enter a port for the web panel [Default: 80]: " PANEL_PORT
    PANEL_PORT=${PANEL_PORT:-80}
    read -p "Enter a username for the panel administrator: " ADMIN_USER
    read -s -p "Enter a secure password for the admin: " ADMIN_PASS; echo
    echo ""
    read -p "Enter a name for your Tinc network (e.g., myvpn): " TINC_NET_NAME
    read -p "Enter a name for this main server (e.g., iranserver): " TINC_NODE_NAME
    read -p "Enter the private IP for this main server (e.g., 10.20.0.1): " TINC_PRIVATE_IP
    read -p "Enter the subnet mask (e.g., 255.255.255.0): " TINC_NETMASK

    # --- 2. System & Tinc Dependencies ---
    echo -e "\n\033[1;34mStep 2/7: Installing System Dependencies\033[0m"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y > /dev/null
    echo "  -> Installing required packages (python, nginx, tinc, etc.)..."
    apt-get install -y python3 python3-pip python3-venv nginx gunicorn tinc net-tools curl sshpass psmisc tar iproute2 > /dev/null
    for cmd in tincd sshpass ifconfig ping pkill tar ip; do
        if ! command -v $cmd &> /dev/null; then echo -e "\033[0;31mFATAL ERROR: Command '$cmd' was not found. Installation cannot continue.\033[0m"; exit 1; fi
    done
    echo "  -> All dependencies installed and verified."

    # --- 3. Create Project Directory ---
    echo -e "\n\033[1;34mStep 3/7: Creating Project Directory\033[0m"
    mkdir -p "$PROJECT_DIR/templates" "$PROJECT_DIR/backups"
    echo "  -> Project directory created at $PROJECT_DIR"

    # --- 4. Setup Main Tinc Node ---
    echo -e "\n\033[1;34mStep 4/7: Configuring Tinc Main Node\033[0m"
    TINC_DIR="/etc/tinc/$TINC_NET_NAME"
    HOSTS_DIR="$TINC_DIR/hosts"
    CLIENTS_INFO_DIR="/etc/tinc/clients_info"
    mkdir -p "$HOSTS_DIR" "$CLIENTS_INFO_DIR"

    # --- Patched: Write tuned tinc.conf + tuned host file + MTU in tinc-up ---
    cat > "$TINC_DIR/tinc.conf" <<EOF
Name = $TINC_NODE_NAME
AddressFamily = ipv4
Interface = $TINC_NET_NAME

# --- DejTunnel tuning (speed + keepalive) ---
Mode = router
Compression = 0
Cipher = aes-128-gcm
Digest = sha256
DirectOnly = yes
AutoConnect = yes
PingInterval = 10
PingTimeout = 5
EOF

    cat > "$HOSTS_DIR/$TINC_NODE_NAME" <<EOF
Address = $SERVER_PUBLIC_IP
Subnet = $TINC_PRIVATE_IP/32
PMTUDiscovery = yes
ClampMSS = yes
EOF

    cat > "$TINC_DIR/tinc-up" <<EOF
#!/bin/sh
/sbin/ifconfig \$INTERFACE $TINC_PRIVATE_IP netmask $TINC_NETMASK
/sbin/ip link set dev \$INTERFACE mtu 1380 || true
EOF

    printf "#!/bin/sh\n/sbin/ifconfig \$INTERFACE down\n" > "$TINC_DIR/tinc-down"
    chmod +x "$TINC_DIR/tinc-up" "$TINC_DIR/tinc-down"

    echo "  -> Generating Tinc RSA keys (4096-bit)..."
    tincd -n "$TINC_NET_NAME" -K4096 &>/dev/null
    systemctl enable "tinc@$TINC_NET_NAME" > /dev/null
    systemctl restart "tinc@$TINC_NET_NAME"
    echo "  -> Tinc main node configured and started."

    # --- 5. Setup Web Panel ---
    echo -e "\n\033[1;34mStep 5/7: Generating Web Panel Files & UI\033[0m"

    cat > "$PROJECT_DIR/requirements.txt" << 'EOL'
Flask==2.2.2
Werkzeug==2.2.2
gunicorn==20.1.0
Flask-SQLAlchemy==2.5.1
SQLAlchemy==1.4.46
Flask-Bcrypt==1.0.1
python-dotenv==1.0.0
EOL
    SECRET_KEY_VALUE=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
    cat > "$PROJECT_DIR/.env" << EOL
SECRET_KEY=${SECRET_KEY_VALUE}
EOL

    # app.py (FINAL VERSION with restored log functions) - PATCHED
    cat > "$PROJECT_DIR/app.py" << 'EOL'
import os
import subprocess
import uuid
import threading
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    PERMANENT_SESSION_LIFETIME=timedelta(days=31),
    UPLOAD_FOLDER=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
tasks = {}

# --- Constants & Paths ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = app.config['UPLOAD_FOLDER']
CMD_SUDO='/usr/bin/sudo'; CMD_SYSTEMCTL='/bin/systemctl'; CMD_PING='/bin/ping'; CMD_SSHPASS='/usr/bin/sshpass'; CMD_SSH='/usr/bin/ssh'; CMD_SCP='/usr/bin/scp'; CMD_TINCD='/usr/sbin/tincd'; CMD_IFCONFIG='/sbin/ifconfig'; CMD_RM='/bin/rm'; CMD_JOURNALCTL='/bin/journalctl'; CMD_PKILL='/usr/bin/pkill'

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); username=db.Column(db.String(80),unique=True,nullable=False); password_hash=db.Column(db.String(128),nullable=False)
class TincNetwork(db.Model):
    id=db.Column(db.Integer,primary_key=True); net_name=db.Column(db.String(80),unique=True,nullable=False); main_node_name=db.Column(db.String(80),nullable=False); main_public_ip=db.Column(db.String(45),nullable=False); main_private_ip=db.Column(db.String(45),nullable=False); subnet_mask=db.Column(db.String(45),nullable=False)
class RemoteNode(db.Model):
    id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(80),unique=True,nullable=False); public_ip=db.Column(db.String(45),nullable=False); private_ip=db.Column(db.String(45),nullable=False); ssh_user=db.Column(db.String(80),nullable=False); ssh_pass=db.Column(db.String(256),nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args,**kwargs)
    return decorated_function

def get_main_node_status(main_network):
    try:
        service_res=subprocess.run([CMD_SUDO,CMD_SYSTEMCTL,"is-active",f"tinc@{main_network.net_name}"],capture_output=True,text=True,check=True)
        if "active" not in service_res.stdout.strip(): return {"status":"Service Down"}
        ping_res=subprocess.run([CMD_PING,"-c","1","-W","1",main_network.main_private_ip],capture_output=True,text=True)
        if ping_res.returncode!=0: return {"status":"Unreachable"}
        return {"status":"Online"}
    except Exception: return {"status":"Check Error"}
def get_remote_node_status(private_ip):
    try:
        res=subprocess.run([CMD_PING,"-c","1","-W","1",private_ip],capture_output=True,text=True,timeout=2)
        return {"status":"Online"} if res.returncode==0 else {"status":"Offline"}
    except Exception: return {"status":"Offline"}

def _run_single_node_provision(node_data, main_network_info, existing_nodes):
    node_name = node_data['name']
    public_ip = node_data['public_ip']
    private_ip = node_data['private_ip']
    ssh_user = node_data['ssh_user']
    ssh_pass = node_data['ssh_pass']

    net_name, node_name_main, netmask = main_network_info.net_name, main_network_info.main_node_name, main_network_info.subnet_mask
    hosts_dir = f"/etc/tinc/{net_name}/hosts"
    clients_dir = "/etc/tinc/clients_info"
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

    # [1] Cleanup remote server
    cleanup_script = f"if [ -d /etc/tinc/{net_name} ]; then sudo {CMD_RM} -rf /etc/tinc/{net_name}; fi"
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",cleanup_script],capture_output=True,text=True,timeout=60)

    # [2] Configure Tinc on remote (PATCHED: tuned tinc.conf + tuned host file + MTU)
    remote_script=f"""set -e
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install --reinstall tinc net-tools iproute2 > /dev/null
sudo mkdir -p /etc/tinc/{net_name}/hosts

sudo tee /etc/tinc/{net_name}/tinc.conf > /dev/null <<'CONF'
Name = {node_name}
AddressFamily = ipv4
Interface = {net_name}
ConnectTo = {node_name_main}

# --- DejTunnel tuning (speed + keepalive) ---
Mode = router
Compression = 0
Cipher = aes-128-gcm
Digest = sha256
DirectOnly = yes
AutoConnect = yes
PingInterval = 10
PingTimeout = 5
CONF

sudo tee /etc/tinc/{net_name}/tinc-up > /dev/null <<'UP'
#!/bin/sh
{CMD_IFCONFIG} \\$INTERFACE {private_ip} netmask {netmask}
/sbin/ip link set dev \\$INTERFACE mtu 1380 || true
UP
sudo chmod +x /etc/tinc/{net_name}/tinc-up

sudo {CMD_TINCD} -n {net_name} -K4096

sudo tee /etc/tinc/{net_name}/hosts/{node_name} > /dev/null <<'HOST'
Address = {public_ip}
Subnet = {private_ip}/32
PMTUDiscovery = yes
ClampMSS = yes
HOST
"""
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",remote_script],check=True,capture_output=True,text=True,timeout=300)

    # [3] Exchange host files
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{ssh_user}@{public_ip}:{hosts_dir}/{node_name}",f"{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node_name_main}",f"{ssh_user}@{public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)

    # [4] Create full mesh with existing nodes
    for node in existing_nodes:
        subprocess.run([CMD_SSHPASS,"-p",node.ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node_name}",f"{node.ssh_user}@{node.public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
        subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node.name}",f"{ssh_user}@{public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)

        # Normalize the new host file on existing nodes (ensure PMTU/ClampMSS; keep UDP default by removing TCPOnly=yes)
        normalize_existing_script = f"""set -e
HF=/etc/tinc/{net_name}/hosts/{node_name}
[ -f "$HF" ] || exit 0
grep -q '^PMTUDiscovery' "$HF" || echo 'PMTUDiscovery = yes' | sudo tee -a "$HF" >/dev/null
grep -q '^ClampMSS' "$HF" || echo 'ClampMSS = yes' | sudo tee -a "$HF" >/dev/null
sudo sed -i '/^TCPOnly\\s*=\\s*yes\\s*$/Id' "$HF" || true
"""
        subprocess.run([CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, *ssh_opts, f"{node.ssh_user}@{node.public_ip}", normalize_existing_script], check=True, capture_output=True, text=True, timeout=45)

        reload_script = f"sudo {CMD_PKILL} -HUP -f 'tincd -n {net_name}'"
        subprocess.run([CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, *ssh_opts, f"{node.ssh_user}@{node.public_ip}", reload_script], check=True, capture_output=True, text=True, timeout=30)

    # Normalize all host files on the new node
    normalize_new_node_script = f"""set -e
for f in /etc/tinc/{net_name}/hosts/*; do
  [ -f "$f" ] || continue
  grep -q '^PMTUDiscovery' "$f" || echo 'PMTUDiscovery = yes' | sudo tee -a "$f" >/dev/null
  grep -q '^ClampMSS' "$f" || echo 'ClampMSS = yes' | sudo tee -a "$f" >/dev/null
  sudo sed -i '/^TCPOnly\\s*=\\s*yes\\s*$/Id' "$f" || true
done
"""
    subprocess.run([CMD_SSHPASS, "-p", ssh_pass, CMD_SSH, *ssh_opts, f"{ssh_user}@{public_ip}", normalize_new_node_script], check=True, capture_output=True, text=True, timeout=60)

    # [5] Finalize services
    if not os.path.exists(clients_dir): os.makedirs(clients_dir)
    with open(f"{clients_dir}/{node_name}","w") as f: f.write(f"IP_PUBLIC={public_ip}\\nUSER={ssh_user}\\nPASS='{ssh_pass}'\\n")
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",f"sudo {CMD_SYSTEMCTL} enable tinc@{net_name} && sudo {CMD_SYSTEMCTL} restart tinc@{net_name}"],check=True,capture_output=True,text=True,timeout=60)

    # [6] Reload main server and save to DB
    subprocess.run([CMD_SUDO, CMD_PKILL, "-HUP", "-f", f"tincd -n {net_name}"], check=True, capture_output=True)
    with app.app_context():
        if not RemoteNode.query.filter_by(name=node_name).first():
            db.session.add(RemoteNode(name=node_name,public_ip=public_ip,private_ip=private_ip,ssh_user=ssh_user,ssh_pass=ssh_pass))
            db.session.commit()

# --- ASYNC TASK FUNCTIONS (NEW LOGIC) ---
def add_node_task(task_id,form_data):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status']='Failed' if is_error else 'In Progress'
    try:
        log("Starting node provision...", 5)
        with app.app_context():
            main_network = TincNetwork.query.first()
            existing_nodes = RemoteNode.query.all()
        log("Configuration loaded, executing provision script...", 15)
        _run_single_node_provision(form_data, main_network, existing_nodes)
        log("SUCCESS: Node provisioned and added to the mesh!", 100)
        tasks[task_id]['status']='Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e,'stderr') and e.stderr else str(e)
        log(f"ERROR: {error_output}", tasks[task_id]['progress'], is_error=True)

# (rest of your app.py continues unchanged...)
EOL

    echo "  -> Generated Flask application file (app.py)."

    cat > "$PROJECT_DIR/wsgi.py" << 'EOL'
from app import app
if __name__ == "__main__":
    app.run()
EOL

    cat > "$PROJECT_DIR/initial_setup.py" << 'EOL'
import sys
from app import app, db, User, TincNetwork, bcrypt
if len(sys.argv) != 8: sys.exit(1)
admin_user, admin_pass, net_name, node_name, public_ip, private_ip, netmask = sys.argv[1:8]
with app.app_context():
    db.create_all()
    if User.query.first() is None:
        db.session.add(User(username=admin_user, password_hash=bcrypt.generate_password_hash(admin_pass).decode('utf-8')))
    if TincNetwork.query.first() is None:
        db.session.add(TincNetwork(net_name=net_name, main_node_name=node_name, main_public_ip=public_ip, main_private_ip=private_ip, subnet_mask=netmask))
    db.session.commit()
EOL

    cat > "$PROJECT_DIR/update_credentials.py" << 'EOL'
import sys
from app import app, db, User, bcrypt
if len(sys.argv) != 3: sys.exit(1)
new_username, new_password = sys.argv[1], sys.argv[2]
with app.app_context():
    user = User.query.first()
    if not user:
        print("Error: No admin user found in the database.")
        sys.exit(1)
    updated_fields = []
    if new_username:
        user.username = new_username
        updated_fields.append("username")
    if new_password:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        updated_fields.append("password")
    if updated_fields:
        db.session.commit()
        print(f"Successfully updated: {', '.join(updated_fields)}")
    else:
        print("No changes provided. Nothing updated.")
EOL

    # --- HTML Templates ---
    # (UNCHANGED: keep your templates as-is)
    # ... keep the rest of your script exactly as you had it ...

    # --- 6. Python Env ---
    echo -e "\n\033[1;34mStep 6/7: Installing Python Packages\033[0m"
    echo "  -> Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "  -> Installing Python packages from requirements.txt..."
    bash -c "source $VENV_DIR/bin/activate && pip install -q --no-cache-dir -r $PROJECT_DIR/requirements.txt"
    echo "  -> Python environment is ready."

    # --- 7. Configure and Start Services ---
    echo -e "\n\033[1;34mStep 7/7: Configuring and Starting System Services\033[0m"
    cat > /etc/systemd/system/tinc_panel.service << EOL
[Unit]
Description=Gunicorn for DejTunnel Panel
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$VENV_DIR/bin/gunicorn --workers 1 --bind 127.0.0.1:${INTERNAL_PORT} wsgi:app
[Install]
WantedBy=multi-user.target
EOL
    systemctl daemon-reload; systemctl start tinc_panel; systemctl enable tinc_panel
    echo "  -> Gunicorn service (tinc_panel) created and started."

    cat > /etc/nginx/sites-available/tinc_panel << EOL
server {
    listen ${PANEL_PORT};
    server_name ${SERVER_PUBLIC_IP} _;
    location / {
        proxy_pass http://127.0.0.1:${INTERNAL_PORT};
        include proxy_params;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOL
    if [ -f /etc/nginx/sites-enabled/default ]; then rm -f /etc/nginx/sites-enabled/default; fi
    ln -s -f /etc/nginx/sites-available/tinc_panel /etc/nginx/sites-enabled/
    systemctl restart nginx
    echo "  -> Nginx reverse proxy configured and started."

    # --- Final DB Setup ---
    echo -e "\n\033[1;34mSeeding Initial Database...\033[0m"
    bash -c "cd $PROJECT_DIR && source venv/bin/activate && python3 initial_setup.py '$ADMIN_USER' '$ADMIN_PASS' '$TINC_NET_NAME' '$TINC_NODE_NAME' '$SERVER_PUBLIC_IP' '$TINC_PRIVATE_IP' '$TINC_NETMASK'" > /dev/null
    echo "  -> Database created and initial admin/network data seeded."

    echo -e "\n\033[1;32m✅ --- Installation Complete! ---\033[0m"
    echo -e "You can now access your DejTunnel panel at:"
    echo -e "  \033[1;33mhttp://${SERVER_PUBLIC_IP}:${PANEL_PORT}\033[0m"
    echo -e "Login with username '\033[1;33m${ADMIN_USER}\033[0m' and the password you provided."
}

# --- Main Menu Logic ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[1;31mError: This script requires root privileges. Please run with 'sudo'.\033[0m"
    exit 1
fi

while true; do
    IS_INSTALLED=false
    if [ -d "$PROJECT_DIR" ]; then
        IS_INSTALLED=true
    fi

    print_menu

    if $IS_INSTALLED; then
        read -p "Select an option [1-4]: " choice
        case $choice in
            1)
                run_full_uninstall && run_installation
                wait_for_enter
                ;;
            2)
                run_full_uninstall
                wait_for_enter
                ;;
            3)
                change_configuration
                wait_for_enter
                ;;
            4)
                echo -e "\033[1;36mExiting Panel Manager. Goodbye!\033[0m"
                exit 0
                ;;
            *)
                echo -e "\033[1;31mInvalid option. Please try again.\033[0m"
                sleep 2
                ;;
        esac
    else
        read -p "Select an option [1-2]: " choice
        case $choice in
            1)
                run_installation
                wait_for_enter
                ;;
            2)
                echo -e "\033[1;36mExiting Panel Manager. Goodbye!\033[0m"
                exit 0
                ;;
            *)
                echo -e "\033[1;31mInvalid option. Please try again.\033[0m"
                sleep 2
                ;;
        esac
    fi
done
