from flask import Flask, render_template, request, jsonify
import threading, time, subprocess, sqlite3, json, os, socket
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, send, Packet, ShortField, StrFixedLenField
import numpy as np
import psutil

app = Flask(_name_)
lock = threading.Lock()

DB_FILE = "aionet1.db"
CONFIG_FILE = "aionet_priorities.json"
STATS_WINDOW = 20
ACTIVE_WINDOW = 20  # seconds

application_cpu = {}
port_to_app = {}
flow_stats = defaultdict(lambda: {
    'pkt_count': 0,
    'total_size': 0,
    'first_seen': None,
    'last_seen': None,
    'analyzer': None
})

# === Custom Packet Definition ===
class MyPacket(Packet):
    name = "MyPacket"
    fields_desc = [
        ShortField("field1", 0),
        StrFixedLenField("field2", b"", length=16),
        StrFixedLenField("field3", b"", length=12),
        StrFixedLenField("field4", b"", length=17),
        StrFixedLenField("data", b"", length=83)
    ]

class PriorityConfig:
    def _init_(self):
        self.app_bonuses = {}
        self.port_rules = {}
        self.load()
    def load(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                self.app_bonuses = cfg.get('application_bonuses', {})
                self.port_rules = cfg.get('port_rules', {})
        else:
            self.app_bonuses = {'zoom': 0.5, 'teams': 0.5, 'chrome': 0.2}
            self.port_rules = {'8801': {"priority": "high"}, '3478': {"priority": "high"}}
priority_config = PriorityConfig()

class FlowAnalyzer:
    def _init_(self):
        self.packet_sizes = deque(maxlen=STATS_WINDOW)
        self.packet_times = deque(maxlen=STATS_WINDOW)
        self.protocols = set()
    def add_packet(self, pkt):
        now = time.time()
        self.packet_sizes.append(len(pkt))
        self.packet_times.append(now)
        if TCP in pkt and pkt[TCP].dport in [443, 8443]:
            self.protocols.add('encrypted')
    @property
    def avg_bandwidth(self):
        if len(self.packet_times) < 2:
            return 0
        duration = self.packet_times[-1] - self.packet_times[0]
        if duration <= 0:
            return 0
        return sum(self.packet_sizes) * 8 / duration / 1000  # kbps
    @property
    def avg_interval(self):
        return np.mean(np.diff(self.packet_times)) if len(self.packet_times) > 1 else 0

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS app_priorities (
            app_name TEXT PRIMARY KEY,
            base_priority TEXT,
            user_override TEXT,
            last_updated DATETIME)""")
        c.execute("""CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY,
            app_name TEXT,
            current_priority TEXT,
            override_priority TEXT,
            timestamp TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS unknown_apps (
            id INTEGER PRIMARY KEY,
            app_signature TEXT UNIQUE,
            first_seen DATETIME,
            last_seen DATETIME,
            assigned_priority TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS app_metrics (
            id INTEGER PRIMARY KEY,
            app_name TEXT,
            cpu_percent REAL,
            bandwidth REAL,
            priority TEXT,
            timestamp TEXT)""")
        conn.commit()

def compute_priority(app_name, flow_data):
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT user_override FROM app_priorities WHERE app_name = ?", (app_name,))
        row = c.fetchone()
        if row and row[0]:
            return row[0]
    stats = flow_data['stats']
    analyzer = flow_data['analyzer']
    cpu = min(application_cpu.get(app_name, 0) / 40, 1)
    bw = min(stats['bw_kbps'] / 10000, 1)
    pkts = min(stats['pkt_count'] / 500, 1)
    score = (0.5 * cpu) + (0.3 * bw) + (0.2 * pkts)
    score += priority_config.app_bonuses.get(app_name.lower(), 0)
    if 'encrypted' in analyzer.protocols:
        score += 0.2
    base_priority = "high" if score > 0.75 else "medium" if score > 0.45 else "low"
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT INTO app_priorities (app_name, base_priority, last_updated)
            VALUES (?, ?, ?)
            ON CONFLICT(app_name) DO UPDATE SET base_priority=excluded.base_priority, last_updated=excluded.last_updated
        """, (app_name, base_priority, now))
        conn.commit()
    return base_priority

def log_unknown_app(pkt, priority):
    now = datetime.now().isoformat()
    signature = f"{pkt[IP].src}:{pkt[IP].dst}:{pkt[IP].proto}"
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT INTO unknown_apps (app_signature, first_seen, last_seen, assigned_priority)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(app_signature) DO UPDATE SET last_seen=excluded.last_seen, assigned_priority=excluded.assigned_priority
        """, (signature, now, now, priority))
        conn.commit()

def process_packet(pkt):
    try:
        if IP not in pkt or (TCP not in pkt and UDP not in pkt): return
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
        ip_layer = pkt[IP]
        flow_key = (ip_layer.src, ip_layer.dst, l4.dport)
        now = datetime.now()
        with lock:
            flow = flow_stats[flow_key]
            if not flow['analyzer']:
                flow['analyzer'] = FlowAnalyzer()
                flow['first_seen'] = now
            flow['analyzer'].add_packet(pkt)
            flow['pkt_count'] += 1
            flow['total_size'] += len(pkt)
            flow['last_updated'] = now
            app_name = port_to_app.get(l4.dport, "unknown")
            cpu_pct = application_cpu.get(app_name, 0.0) if app_name != "unknown" else 0.0
            bw_kbps = flow['analyzer'].avg_bandwidth
            if app_name == "unknown":
                prio = "high" if flow['analyzer'].avg_interval < 0.01 else "medium"
                log_unknown_app(pkt, prio)
            else:
                flow_data = {'stats': {'bw_kbps': bw_kbps, 'pkt_count': flow['pkt_count']}, 'analyzer': flow['analyzer']}
                prio = compute_priority(app_name, flow_data)
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("INSERT INTO app_metrics (app_name, cpu_percent, bandwidth, priority, timestamp) VALUES (?, ?, ?, ?, ?)",
                             (app_name, cpu_pct, bw_kbps, prio, now.isoformat()))
                conn.commit()
    except Exception as e:
        print(f"[ERROR] {e}")

def monitor_application_cpu():
    while True:
        try:
            result = subprocess.run(['top', '-b', '-n1'], capture_output=True, text=True)
            cpu_data = {}
            in_processes = False
            for line in result.stdout.split('\n'):
                if 'PID' in line and 'COMMAND' in line: in_processes = True; continue
                if in_processes and line.strip():
                    parts = line.split()
                    if len(parts) >= 9:
                        cpu = float(parts[8])
                        cmd = parts[-1]
                        cpu_data[cmd] = cpu_data.get(cmd, 0) + cpu
            with lock:
                application_cpu.clear()
                application_cpu.update(cpu_data)
            time.sleep(2)
        except Exception as e:
            print(f"[CPU MONITOR ERROR] {e}")
            time.sleep(5)

def update_port_mapping():
    while True:
        try:
            conns = psutil.net_connections('inet')
            temp_map = {}
            for conn in conns:
                if not (conn.laddr and conn.pid): continue
                if conn.type == socket.SOCK_STREAM and conn.status != psutil.CONN_ESTABLISHED: continue
                try:
                    proc = psutil.Process(conn.pid)
                    app = proc.name()
                    temp_map[conn.laddr.port] = app
                    if conn.raddr:
                        temp_map[conn.raddr.port] = app
                except: continue
            with lock:
                port_to_app.clear()
                port_to_app.update(temp_map)
            time.sleep(2)
        except Exception as e:
            print(f"[PORT MONITOR ERROR] {e}")

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/metrics')
def metrics():
    try:
        now = time.time()
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT m.app_name, m.cpu_percent, m.bandwidth, m.priority, MAX(m.timestamp), p.user_override
                FROM app_metrics m
                LEFT JOIN app_priorities p ON m.app_name = p.app_name
                GROUP BY m.app_name
            """)
            rows = c.fetchall()
            metrics = {}
            for r in rows:
                last_seen = datetime.fromisoformat(r[4]).timestamp() if r[4] else 0
                if now - last_seen < ACTIVE_WINDOW:
                    metrics[r[0]] = {
                        'cpu': r[1],
                        'bw': r[2],
                        'prio': r[3],
                        'override': r[5] if r[5] else ""
                    }
            c.execute("SELECT app_signature, last_seen, assigned_priority FROM unknown_apps ORDER BY last_seen DESC LIMIT 10")
            alerts = [{'sig': r[0], 'time': r[1], 'prio': r[2]} for r in c.fetchall()]
        return jsonify({'metrics': metrics, 'alerts': alerts})
    except Exception as e:
        print(f"Metrics error: {e}")
        return jsonify({'metrics': {}, 'alerts': []})

@app.route('/override', methods=['POST'])
def override():
    app_name = request.form['app_name']
    new_priority = request.form['override_priority'].lower()
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO feedback (app_name, current_priority, override_priority, timestamp) VALUES (?, ?, ?, ?)",
                     (app_name, "auto", new_priority, now))
        if new_priority:
            conn.execute("""
                INSERT INTO app_priorities (app_name, user_override, last_updated)
                VALUES (?, ?, ?)
                ON CONFLICT(app_name) DO UPDATE SET user_override=excluded.user_override, last_updated=excluded.last_updated
            """, (app_name, new_priority, now))
        else:
            conn.execute("""
                UPDATE app_priorities SET user_override=NULL, last_updated=?
                WHERE app_name=?
            """, (now, app_name))
        conn.commit()
    return jsonify(status="success")

# === Custom Packet Route ===
@app.route('/send_custom_packet', methods=['POST'])
def send_custom_packet():
    try:
        dst_ip = request.form.get("dst_ip", "127.0.0.1")
        dport = int(request.form.get("dport", 9999))
        field1 = int(request.form.get("field1", 123))
        field2 = request.form.get("field2", "abcdefghijklmno1").encode().ljust(16)[:16]
        field3 = request.form.get("field3", "123456789012").encode().ljust(12)[:12]
        field4 = request.form.get("field4", "abcdefghijklmnopq").encode().ljust(17)[:17]
        data = request.form.get("data", "x"*83).encode().ljust(83)[:83]
        pkt = IP(dst=dst_ip)/UDP(dport=dport)/MyPacket(
            field1=field1,
            field2=field2,
            field3=field3,
            field4=field4,
            data=data
        )
        send(pkt, verbose=0)
        return jsonify({"status": "success", "message": f"Sent custom packet to {dst_ip}:{dport}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    init_db()
    threading.Thread(target=update_port_mapping, daemon=True).start()
    threading.Thread(target=monitor_application_cpu, daemon=True).start()
    threading.Thread(target=lambda: sniff(prn=process_packet, filter="ip", store=False), daemon=True).start()
    app.run(debug=False, host='0.0.0.0', port=5050)
