from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import subprocess
import os
import sqlite3
from datetime import datetime
import shutil
from functools import wraps
import glob
from dateutil.parser import parse
import re
import time
import psutil
import logging
import sys
from dotenv import load_dotenv

# 获取当前脚本所在目录（openvpn-webui 根目录）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# openvpn-webui 根目录
ROOT_DIR = os.path.dirname(BASE_DIR)

# 加载 .env 文件
load_dotenv(os.path.join(ROOT_DIR, 'config', '.env'))

# 配置默认值（从 .env 文件加载，必要时提供内部路径的回退值）
CONFIG = {
    'ADMIN_USERNAME': os.getenv('ADMIN_USERNAME'),
    'ADMIN_PASSWORD': os.getenv('ADMIN_PASSWORD'),
    'OPENVPN_CONFIG_PATH': os.getenv('OPENVPN_CONFIG_PATH'),
    'OPENVPN_STATUS_LOG': os.getenv('OPENVPN_STATUS_LOG'),
    'OPENVPN_LOG': os.getenv('OPENVPN_LOG'),
    'OPENVPN_CLIENT_CONFIGS_DIR': os.getenv('OPENVPN_CLIENT_CONFIGS_DIR'),
    'OPENVPN_EASYRSA_DIR': os.getenv('OPENVPN_EASYRSA_DIR'),
    'OPENVPN_TLS_KEY': os.getenv('OPENVPN_TLS_KEY'),
    'OPENVPN_CA_CERT': os.getenv('OPENVPN_CA_CERT'),
    'OPENVPN_CLIENT_COMMON': os.getenv('OPENVPN_CLIENT_COMMON'),
    'OPENVPN_BACKUP_DIR': os.getenv('OPENVPN_BACKUP_DIR'),
    'DATABASE_PATH': os.getenv('DATABASE_PATH', os.path.join(ROOT_DIR, 'openvpn.db')),
    'WEBUI_LOG_PATH': os.getenv('WEBUI_LOG_PATH', os.path.join(ROOT_DIR, 'log', 'openvpn_webui.log')),
    'FLASK_HOST': os.getenv('FLASK_HOST'),
    'FLASK_PORT': int(os.getenv('FLASK_PORT')),
    'FLASK_DEBUG': os.getenv('FLASK_DEBUG').lower() == 'true',
}

# 配置日志
logging.basicConfig(
    filename=CONFIG['WEBUI_LOG_PATH'],
    level=logging.DEBUG,
    format='%(asctime)s: %(levelname)s: %(message)s'
)

# 初始化 Flask 应用，指定模板目录
app = Flask(__name__, template_folder=os.path.join(ROOT_DIR, 'static'))
app.secret_key = os.urandom(24)

# 数据库初始化
def init_db():
    try:
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users 
                        (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, 
                         role TEXT, status TEXT, created_at TIMESTAMP)''')
            c.execute('''CREATE TABLE IF NOT EXISTS vpn_users 
                        (id INTEGER PRIMARY KEY, username TEXT UNIQUE, ovpn_file TEXT, 
                         created_at TIMESTAMP)''')
            c.execute('''CREATE TABLE IF NOT EXISTS traffic_history 
                        (id INTEGER PRIMARY KEY, timestamp REAL, rx_mb REAL, tx_mb REAL)''')
            c.execute('SELECT COUNT(*) FROM users')
            user_count = c.fetchone()[0]
            if user_count == 0:
                c.execute('INSERT INTO users (username, password, role, status, created_at) VALUES (?, ?, ?, ?, ?)',
                          (CONFIG['ADMIN_USERNAME'], CONFIG['ADMIN_PASSWORD'], 'admin', 'active', datetime.now()))
            conn.commit()
        logging.info("数据库初始化成功")
        sync_vpn_users()  # 同步 VPN 用户
    except Exception as e:
        logging.error(f"数据库初始化失败: {str(e)}")
        raise

# 同步 EasyRSA index.txt 和 vpn_users 表
def sync_vpn_users():
    try:
        index_file = f"{CONFIG['OPENVPN_EASYRSA_DIR']}/pki/index.txt"
        client_configs_dir = CONFIG['OPENVPN_CLIENT_CONFIGS_DIR']
        
        if not os.path.exists(index_file):
            logging.warning(f"EasyRSA index.txt 不存在: {index_file}")
            return
        
        # 读取 index.txt
        valid_users = []
        with open(index_file, 'r') as f:
            for line in f:
                if line.startswith('V'):  # 有效证书
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        cn = parts[3].split('=')[1]
                        if cn != 'server':  # 排除服务器证书
                            valid_users.append(cn)
        
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            c = conn.cursor()
            c.execute('SELECT username, ovpn_file FROM vpn_users')
            db_users = {row[0]: row[1] for row in c.fetchall()}
            
            # 同步逻辑
            for username in valid_users:
                if username not in db_users:
                    # 新用户，生成 .ovpn 文件并添加到数据库
                    ovpn_file = f"{client_configs_dir}/{username}.ovpn"
                    if not os.path.exists(ovpn_file):
                        generate_ovpn_file(username, ovpn_file)
                    c.execute('INSERT OR IGNORE INTO vpn_users (username, ovpn_file, created_at) VALUES (?, ?, ?)',
                              (username, ovpn_file, datetime.now()))
                    logging.info(f"同步添加用户 {username} 到数据库")
            
            # 删除数据库中不存在于 index.txt 的用户
            for username in db_users:
                if username not in valid_users:
                    c.execute('DELETE FROM vpn_users WHERE username = ?', (username,))
                    if os.path.exists(db_users[username]):
                        os.remove(db_users[username])
                    logging.info(f"同步删除用户 {username} 从数据库")
            
            conn.commit()
        logging.info("VPN 用户同步完成")
    except Exception as e:
        logging.error(f"同步 VPN 用户失败: {str(e)}")

# 生成 .ovpn 文件
def generate_ovpn_file(username, ovpn_file):
    try:
        client_configs_dir = CONFIG['OPENVPN_CLIENT_CONFIGS_DIR']
        easyrsa_dir = CONFIG['OPENVPN_EASYRSA_DIR']
        tls_key_file = CONFIG['OPENVPN_TLS_KEY']
        
        if not os.path.exists(client_configs_dir):
            os.makedirs(client_configs_dir)
        
        with open(CONFIG['OPENVPN_CLIENT_COMMON'], 'r') as f:
            client_common = f.read()
        with open(f'{easyrsa_dir}/pki/issued/{username}.crt', 'r') as f:
            cert_content = f.read()
            cert = clean_certificate_content(cert_content)
        with open(f'{easyrsa_dir}/pki/private/{username}.key', 'r') as f:
            key = f.read()
        with open(CONFIG['OPENVPN_CA_CERT'], 'r') as f:
            ca = f.read()
        
        tls_key = ''
        if os.path.exists(tls_key_file):
            with open(tls_key_file, 'r') as f:
                tls_key = f.read()
        
        with open(ovpn_file, 'w') as f:
            f.write(client_common)
            f.write('\n<ca>\n')
            f.write(ca)
            f.write('</ca>\n<cert>\n')
            f.write(cert)
            f.write('</cert>\n<key>\n')
            f.write(key)
            f.write('</key>\n')
            if tls_key:
                f.write('<tls-crypt>\n')
                f.write(tls_key)
                f.write('</tls-crypt>\n')
        
        logging.info(f"生成 .ovpn 文件: {ovpn_file}")
    except Exception as e:
        logging.error(f"生成 .ovpn 文件失败 ({username}): {str(e)}")

# 权限检查装饰器
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
                c = conn.cursor()
                c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
                user_role = c.fetchone()[0]
                if user_role != role:
                    return jsonify({'status': 'error', 'message': '无权限访问'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 清理证书内容，仅保留 PEM 格式
def clean_certificate_content(content):
    pattern = r'-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----\n'
    matches = re.findall(pattern, content, re.DOTALL)
    if matches:
        return matches[0]
    return content

# 格式化连接时长
def format_duration(seconds):
    if not seconds or seconds < 0:
        return "0s"
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = seconds % 60
    result = []
    if hours > 0:
        result.append(f"{hours}h")
    if minutes > 0:
        result.append(f"{minutes}m")
    result.append(f"{secs:.1f}s")
    return "".join(result)

# 从日志中提取连接信息
def get_connection_info_from_logs():
    status_file = CONFIG['OPENVPN_STATUS_LOG']
    log_file = CONFIG['OPENVPN_LOG']
    connections = []
    diagnostics = []
    current_time = time.time()
    # 定义连接超时时间（秒），超过此时间未更新的连接视为断开
    CONNECTION_TIMEOUT = 60  # 1分钟

    try:
        # Step 1: Check status file (primary source)
        status_mtime = 0
        if os.path.exists(status_file):
            status_mtime = os.path.getmtime(status_file)
            if current_time - status_mtime > 120:  # Status file older than 2 minutes
                diagnostics.append(f"Status file {status_file} is stale (last modified {int(current_time - status_mtime)}s ago)")
            else:
                with open(status_file, 'r') as f:
                    lines = f.readlines()
                    client_list_found = False
                    for line in lines:
                        if line.startswith('CLIENT_LIST'):
                            client_list_found = True
                            parts = line.strip().split(',')
                            if len(parts) < 9:
                                diagnostics.append(f"Skipping malformed CLIENT_LIST line: {line.strip()}")
                                continue
                            username = parts[1]
                            connected_since = parts[8]  # Connected since timestamp
                            try:
                                connection_time = parse(connected_since)
                                duration = current_time - connection_time.timestamp()
                                if duration > CONNECTION_TIMEOUT:
                                    diagnostics.append(f"Skipping stale connection for {username} (connected {duration}s ago)")
                                    continue
                            except (ValueError, TypeError) as e:
                                diagnostics.append(f"Failed to parse connected_since '{connected_since}' for {username}: {str(e)}")
                                connection_time = None
                                duration = 0

                            connections.append({
                                'username': username,
                                'real_ip': parts[2].split(':')[0],
                                'virtual_ip': parts[3],
                                'connected_since': connected_since,
                                'start_time': connected_since,
                                'duration': format_duration(duration),
                                'bytes_received': int(parts[5]) if parts[5].isdigit() else 0,
                                'bytes_sent': int(parts[6]) if parts[6].isdigit() else 0
                            })
                    if client_list_found:
                        diagnostics.append(f"Found {len(connections)} active connections in status file")
                        return connections, diagnostics
                    diagnostics.append(f"No CLIENT_LIST entries found in {status_file}")
        
        diagnostics.append(f"Status file {status_file} {'missing' if not os.path.exists(status_file) else 'empty or no valid connections'}")

        # Step 2: Fallback to log file (less reliable, used only if status file is unavailable)
        log_files = glob.glob(f"{log_file}*")
        log_files.sort(key=os.path.getmtime, reverse=True)  # Read newest first
        if not log_files:
            diagnostics.append(f"No log files found at {log_file}*")
            return [], diagnostics
        
        selected_log = log_files[0]
        log_mtime = os.path.getmtime(selected_log)
        if current_time - log_mtime > 120:  # Log file older than 2 minutes
            diagnostics.append(f"Log file {selected_log} is stale (last modified {int(current_time - log_mtime)}s ago)")
        
        diagnostics.append(f"Using log file {selected_log} for fallback (mtime: {datetime.fromtimestamp(log_mtime)})")
        
        with open(selected_log, 'r') as f:
            lines = f.readlines()
        
        # Patterns for connection detection
        patterns = [
            (re.compile(r'(\S+)/(\d+\.\d+\.\d+\.\d+):(\d+)\s+SENT CONTROL \[(\S+)\]:.*PUSH_REPLY'), 'PUSH_REPLY'),
            (re.compile(r'(\S+)/(\d+\.\d+\.\d+\.\d+):(\d+)\s+MULTI: Learn: (\S+) -> \1/\2:\3'), 'MULTI_LEARN'),
            (re.compile(r'\[(.*?)\]\s+(\S+)/(\d+\.\d+\.\d+\.\d+):(\d+)\s+VERIFY OK: depth=0, CN=(\S+)'), 'VERIFY_OK'),
            (re.compile(r'\[(.*?)\]\s+(\S+)/(\d+\.\d+\.\d+\.\d+):(\d+)\s+.*Initialization Sequence Completed'), 'INIT_COMPLETED'),
            (re.compile(r'\[(.*?)\]\s+(\S+)/(\d+\.\d+\.\d+\.\d+):(\d+)\s+.*AUTH_SUCCESS'), 'AUTH_SUCCESS')
        ]
        
        # Pattern for detecting disconnections
        disconnect_pattern = re.compile(r'(\S+)/(\d+\.\d+\.\d+\.\d+):(\d+)\s+Connection reset')
        
        seen_usernames = set()
        for line in reversed(lines):
            # Check for disconnection
            disconnect_match = disconnect_pattern.search(line)
            if disconnect_match:
                username, real_ip, port = disconnect_match.groups()
                seen_usernames.add(username)
                diagnostics.append(f"Detected disconnection for {username} at {real_ip}:{port}")
                continue
            
            for pattern, pattern_name in patterns:
                match = pattern.search(line)
                if match:
                    if pattern_name == 'MULTI_LEARN':
                        username, real_ip, port, virtual_ip = match.groups()
                        timestamp_str = None
                    elif pattern_name == 'PUSH_REPLY':
                        username, real_ip, port, username_confirm = match.groups()
                        if username != username_confirm:
                            diagnostics.append(f"Username mismatch in PUSH_REPLY: {username} vs {username_confirm}")
                            continue
                        virtual_ip = 'N/A'
                        timestamp_str = None
                    else:
                        timestamp_str, username, real_ip, port, *extra = match.groups()
                        virtual_ip = 'N/A'
                    
                    if username in seen_usernames:
                        continue
                    
                    if virtual_ip == 'N/A':
                        for v_line in lines:
                            v_match = re.search(rf'{username}/{real_ip}:{port}\s+MULTI: Learn: (\S+) -> {username}/{real_ip}:{port}', v_line)
                            if v_match:
                                virtual_ip = v_match.group(1)
                                diagnostics.append(f"Found virtual IP {virtual_ip} for {username} in MULTI_LEARN")
                                break
                    
                    try:
                        if timestamp_str:
                            connection_time = parse(timestamp_str, fuzzy=True)
                            duration = current_time - connection_time.timestamp()
                            if duration > CONNECTION_TIMEOUT:
                                diagnostics.append(f"Skipping stale log entry for {username} (connected {duration}s ago)")
                                continue
                        else:
                            connection_time = datetime.fromtimestamp(log_mtime)
                            duration = current_time - log_mtime
                            diagnostics.append(f"No timestamp in {pattern_name} for {username}, using log mtime {connection_time}")
                    except (ValueError, TypeError) as e:
                        diagnostics.append(f"Failed to parse timestamp '{timestamp_str or 'None'}' for {username} in {pattern_name}: {str(e)}")
                        connection_time = datetime.fromtimestamp(log_mtime)
                        duration = current_time - log_mtime
                    
                    start_time_str = connection_time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    connections.append({
                        'username': username,
                        'real_ip': real_ip,
                        'virtual_ip': virtual_ip,
                        'connected_since': start_time_str,
                        'start_time': start_time_str,
                        'duration': format_duration(duration),
                        'bytes_received': 0,
                        'bytes_sent': 0
                    })
                    seen_usernames.add(username)
                    diagnostics.append(f"Matched {pattern_name} for {username} at {start_time_str}")
                    break
        
        diagnostics.append(f"Found {len(connections)} active connections in log file")
        return connections, diagnostics
    
    except PermissionError as e:
        diagnostics.append(f"Permission error accessing files: {str(e)}")
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            f.write(f'{datetime.now()}: Permission error in get_connection_info_from_logs: {str(e)}\n')
        return [], diagnostics
    except Exception as e:
        diagnostics.append(f"Unexpected error: {str(e)}")
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            f.write(f'{datetime.now()}: Error in get_connection_info_from_logs: {str(e)}\n')
        return [], diagnostics

# 从日志中提取连接时间
def get_connection_time_from_logs(username):
    log_files = glob.glob(f"{CONFIG['OPENVPN_LOG']}*")
    log_files.sort(key=os.path.getmtime, reverse=True)
    if not log_files:
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            f.write(f'{datetime.now()}: No log files found for {username}\n')
        return None
    
    patterns = [
        re.compile(rf'\[(.*?)\]\s+{re.escape(username)}/\d+\.\d+\.\d+\.\d+:\d+\s+SENT CONTROL \[{re.escape(username)}\]:.*PUSH_REPLY'),
        re.compile(rf'\[(.*?)\]\s+{re.escape(username)}/\d+\.\d+\.\d+\.\d+:\d+\s+VERIFY OK'),
        re.compile(rf'\[(.*?)\]\s+{re.escape(username)}/\d+\.\d+\.\d+\.\d+:\d+\s+.*Initialization Sequence Completed'),
        re.compile(rf'\[(.*?)\]\s+{re.escape(username)}/\d+\.\d+\.\d+\.\d+:\d+\s+.*AUTH_SUCCESS'),
        re.compile(rf'{re.escape(username)}/\d+\.\d+\.\d+\.\d+:\d+\s+SENT CONTROL \[{re.escape(username)}\]:.*PUSH_REPLY')
    ]
    
    try:
        for log_file in log_files:
            log_mtime = os.path.getmtime(log_file)
            with open(log_file, 'r') as f:
                lines = f.readlines()
            for line in reversed(lines):
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        timestamp_str = match.group(1) if match.groups() else None
                        try:
                            if timestamp_str:
                                timestamp = parse(timestamp_str, fuzzy=True)
                            else:
                                timestamp = datetime.fromtimestamp(log_mtime)
                                with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
                                    f.write(f'{datetime.now()}: No timestamp for {username} in {log_file}, using mtime {timestamp}\n')
                            with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
                                f.write(f'{datetime.now()}: Found connection time {timestamp} for {username} in {log_file}\n')
                            return timestamp
                        except (ValueError, TypeError) as e:
                            with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
                                f.write(f'{datetime.now()}: Failed to parse timestamp "{timestamp_str or "None"}" for {username}: {str(e)}\n')
                            continue
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            f.write(f'{datetime.now()}: No connection time found for {username} in any log file\n')
        return None
    except Exception as e:
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            f.write(f'{datetime.now()}: Error reading log for {username}: {str(e)}\n')
        return None

# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            c = conn.cursor()
            c.execute('SELECT id, role FROM users WHERE username = ? AND password = ?',
                     (data['username'], data['password']))
            user = c.fetchone()
            if user:
                session['user_id'] = user[0]
                session['role'] = user[1]
                return jsonify({'status': 'success'})
            return jsonify({'status': 'error', 'message': '用户名或密码错误'}), 401
    return render_template('login.html')

# 退出登录
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# 修改密码
@app.route('/api/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': '未登录'}), 401
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if new_password != confirm_password:
        return jsonify({'status': 'error', 'message': '新密码与确认密码不匹配'}), 400
    if len(new_password) < 6:
        return jsonify({'status': 'error', 'message': '新密码必须至少6个字符'}), 400
    
    with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
        current_password = c.fetchone()[0]
        if current_password != old_password:
            return jsonify({'status': 'error', 'message': '旧密码错误'}), 401
        c.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, session['user_id']))
        conn.commit()
    
    return jsonify({'status': 'success', 'message': '密码修改成功'})

# 首页
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# 仪表盘数据
@app.route('/api/dashboard', methods=['GET'])
@role_required('admin')
def dashboard():
    try:
        # 同步 VPN 用户以确保数据库与 index.txt 一致
        sync_vpn_users()
        
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM vpn_users')
            total_users = c.fetchone()[0]
        
        connections, _ = get_connection_info_from_logs()
        connected_users = len(connections)
        
        # 使用 systemctl 检查 OpenVPN 服务状态
        server_status = 'abnormal'
        try:
            result = subprocess.run(
                ['systemctl', 'status', 'openvpn-server@server.service'],
                capture_output=True, text=True
            )
            if 'Active: active (running)' in result.stdout:
                server_status = 'running'
        except subprocess.CalledProcessError:
            pass
        
        rx_bytes = tx_bytes = 0
        timestamp = time.time()
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if 'tun0:' in line:
                        parts = line.strip().split()
                        rx_bytes = int(parts[1]) / 1024 / 1024 * 8  # Convert MB to Mb
                        tx_bytes = int(parts[9]) / 1024 / 1024 * 8  # Convert MB to Mb
                        break
        except Exception:
            rx_bytes = tx_bytes = -1
        
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO traffic_history (timestamp, rx_mb, tx_mb) VALUES (?, ?, ?)',
                      (timestamp, rx_bytes if rx_bytes >= 0 else 0, tx_bytes if tx_bytes >= 0 else 0))
            conn.commit()
        
        start_time = request.args.get('start_time', '')
        end_time = request.args.get('end_time', '')
        query = 'SELECT timestamp, rx_mb, tx_mb FROM traffic_history'
        params = []
        if start_time and end_time:
            try:
                start_ts = parse(start_time).timestamp()
                end_ts = parse(end_time).timestamp()
                if start_ts > end_ts:
                    return jsonify({'status': 'error', 'message': '开始时间不能晚于结束时间'}), 400
                query += ' WHERE timestamp >= ? AND timestamp <= ?'
                params.extend([start_ts, end_ts])
            except:
                pass
        elif start_time:
            try:
                start_ts = parse(start_time).timestamp()
                query += ' WHERE timestamp >= ?'
                params.append(start_ts)
            except:
                pass
        elif end_time:
            try:
                end_ts = parse(end_time).timestamp()
                query += ' WHERE timestamp <= ?'
                params.append(end_ts)
            except:
                pass
        
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            c = conn.cursor()
            c.execute(query + ' ORDER BY timestamp ASC', params)
            traffic_data = [{'timestamp': row[0], 'rx_mb': row[1], 'tx_mb': row[2]} for row in c.fetchall()]
        
        timestamps = [d['timestamp'] for d in traffic_data]
        rx_rates = []
        tx_rates = []
        for i in range(1, len(traffic_data)):
            time_diff = traffic_data[i]['timestamp'] - traffic_data[i-1]['timestamp']
            if time_diff > 0:
                rx_rate = (traffic_data[i]['rx_mb'] - traffic_data[i-1]['rx_mb']) / time_diff
                tx_rate = (traffic_data[i]['tx_mb'] - traffic_data[i-1]['tx_mb']) / time_diff
            else:
                rx_rate = tx_rate = 0
            rx_rates.append(rx_rate if rx_rate >= 0 else 0)
            tx_rates.append(tx_rate if tx_rate >= 0 else 0)
        
        return jsonify({
            'status': 'success',
            'total_users': total_users,
            'connected_users': connected_users,
            'server_status': server_status,
            'network_traffic': {
                'rx_mb': round(rx_bytes, 2) if rx_bytes >= 0 else 'N/A',
                'tx_mb': round(tx_bytes, 2) if tx_bytes >= 0 else 'N/A'
            },
            'traffic_history': {
                'timestamps': timestamps[1:] if len(timestamps) > 1 else [],
                'rx_rates': rx_rates,
                'tx_rates': tx_rates
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# OpenVPN 用户管理
@app.route('/api/vpn_users', methods=['GET', 'POST', 'DELETE'])
@role_required('admin')
def manage_vpn_users():
    client_configs_dir = CONFIG['OPENVPN_CLIENT_CONFIGS_DIR']
    easyrsa_dir = CONFIG['OPENVPN_EASYRSA_DIR']
    tls_key_file = CONFIG['OPENVPN_TLS_KEY']
    
    if request.method == 'GET':
        search = request.args.get('search', '')
        with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            if search:
                c.execute('SELECT * FROM vpn_users WHERE username LIKE ?', (f'%{search}%',))
            else:
                c.execute('SELECT * FROM vpn_users')
            vpn_users = [dict(row) for row in c.fetchall()]
        return jsonify(vpn_users)
    
    if request.method == 'POST':
        data = request.json
        username = data['username']
        try:
            if not os.path.exists(client_configs_dir):
                os.makedirs(client_configs_dir)
            
            env = os.environ.copy()
            env['EASYRSA'] = easyrsa_dir
            env['EASYRSA_PKI'] = f'{easyrsa_dir}/pki'
            
            if not os.path.exists(f'{easyrsa_dir}/pki/ca.crt'):
                return jsonify({'status': 'error', 'message': 'EasyRSA 未初始化，请运行 ./easyrsa init-pki 和 ./easyrsa build-ca'}), 500
            
            index_file = f'{easyrsa_dir}/pki/index.txt'
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    lines = f.readlines()
                for line in lines:
                    if f'CN={username}' in line:
                        return jsonify({'status': 'error', 'message': '用户名已存在，请先删除旧用户'}), 400
            
            result = subprocess.run(
                [f'{easyrsa_dir}/easyrsa', '--batch', 'build-client-full', username, 'nopass'],
                env=env, capture_output=True, text=True, check=True
            )
            
            ovpn_file = f'{client_configs_dir}/{username}.ovpn'
            generate_ovpn_file(username, ovpn_file)
            
            with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO vpn_users (username, ovpn_file, created_at) VALUES (?, ?, ?)',
                         (username, ovpn_file, datetime.now()))
                conn.commit()
            
            return jsonify({'status': 'success', 'ovpn_file': ovpn_file})
        except subprocess.CalledProcessError as e:
            return jsonify({'status': 'error', 'message': f'证书生成失败：{e.stderr or "未知错误"}'}), 500
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    if request.method == 'DELETE':
        data = request.json
        username = data['username']
        try:
            env = os.environ.copy()
            env['EASYRSA'] = easyrsa_dir
            env['EASYRSA_PKI'] = f'{easyrsa_dir}/pki'
            
            with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
                c = conn.cursor()
                c.execute('SELECT ovpn_file FROM vpn_users WHERE username = ?', (username,))
                result = c.fetchone()
                if result and os.path.exists(result[0]):
                    os.remove(result[0])
                c.execute('DELETE FROM vpn_users WHERE username = ?', (username,))
                conn.commit()
            
            index_file = f'{easyrsa_dir}/pki/index.txt'
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    lines = f.readlines()
                with open(index_file, 'w') as f:
                    for line in lines:
                        if f'CN={username}' not in line:
                            f.write(line)
            
            try:
                if os.path.exists(f'{easyrsa_dir}/pki/ca.crt'):
                    subprocess.run(
                        [f'{easyrsa_dir}/easyrsa', '--batch', 'revoke', username],
                        env=env, capture_output=True, text=True, check=True
                    )
                    subprocess.run(
                        [f'{easyrsa_dir}/easyrsa', 'gen-crl'],
                        env=env, capture_output=True, text=True, check=True
                    )
                    crl_dest = f"{os.path.dirname(CONFIG['OPENVPN_CONFIG_PATH'])}/crl.pem"
                    if os.path.exists(f'{easyrsa_dir}/pki/crl.pem'):
                        shutil.copy(f'{easyrsa_dir}/pki/crl.pem', crl_dest)
                        subprocess.run(['systemctl', 'restart', 'openvpn-server@server.service'], 
                                     capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as e:
                with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
                    f.write(f'{datetime.now()}: Revoke failed for {username}: {e.stderr}\n')
            
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

# 编辑 VPN 用户配置文件
@app.route('/api/vpn_users/edit/<username>', methods=['GET', 'POST'])
@role_required('admin')
def edit_vpn_user_config(username):
    with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        c = conn.cursor()
        c.execute('SELECT ovpn_file FROM vpn_users WHERE username = ?', (username,))
        result = c.fetchone()
        if not result:
            return jsonify({'status': 'error', 'message': '用户不存在'}), 404
        ovpn_file = result[0]
        
        if request.method == 'GET':
            try:
                if not os.path.exists(ovpn_file):
                    return jsonify({'status': 'error', 'message': '配置文件不存在'}), 404
                with open(ovpn_file, 'r') as f:
                    content = f.read()
                return jsonify({'status': 'success', 'content': content, 'ovpn_file': ovpn_file})
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        if request.method == 'POST':
            data = request.json
            content = data.get('content', '')
            try:
                backup_dir = CONFIG['OPENVPN_BACKUP_DIR']
                if not os.path.exists(backup_dir):
                    os.makedirs(backup_dir)
                backup_path = f"{backup_dir}/{username}.ovpn.{datetime.now().strftime('%Y%m%d%H%M%S')}"
                shutil.copy(ovpn_file, backup_path)
                
                with open(ovpn_file, 'w') as f:
                    f.write(content)
                
                return jsonify({'status': 'success', 'ovpn_file': ovpn_file})
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

# 备份 VPN 用户
@app.route('/api/vpn_users/backup', methods=['POST'])
@role_required('admin')
def backup_vpn_user():
    data = request.json
    username = data['username']
    backup_content = data['backup_content']
    backup_dir = CONFIG['OPENVPN_BACKUP_DIR']
    
    try:
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        backup_path = f"{backup_dir}/{username}.txt.{datetime.now().strftime('%Y%m%d%H%M%S')}"
        with open(backup_path, 'w') as f:
            f.write(backup_content)
        
        return jsonify({'status': 'success', 'backup_path': backup_path})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# 下载 .ovpn 文件
@app.route('/api/vpn_users/download/<username>')
@role_required('admin')
def download_vpn_user(username):
    with sqlite3.connect(CONFIG['DATABASE_PATH']) as conn:
        c = conn.cursor()
        c.execute('SELECT ovpn_file FROM vpn_users WHERE username = ?', (username,))
        result = c.fetchone()
        if not result:
            return jsonify({'status': 'error', 'message': '用户不存在'}), 404
        ovpn_file = result[0]
        if not os.path.exists(ovpn_file):
            return jsonify({'status': 'error', 'message': '配置文件不存在'}), 404
        return send_file(ovpn_file, as_attachment=True)

# 列出配置文件
@app.route('/api/config/files', methods=['GET'])
@role_required('admin')
def list_config_files():
    base_dir = request.args.get('base_dir', os.path.dirname(CONFIG['OPENVPN_CONFIG_PATH']))
    try:
        config_files = []
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith('.conf'):
                    config_files.append(os.path.join(root, file))
        return jsonify({'status': 'success', 'files': config_files})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# 配置文件管理
@app.route('/api/config', methods=['GET', 'POST'])
@role_required('admin')
def manage_config():
    config_file = request.args.get('file', '') if request.method == 'GET' else request.json.get('file', '')
    backup_dir = CONFIG['OPENVPN_BACKUP_DIR']
    
    if request.method == 'GET':
        if not config_file:
            return jsonify({'status': 'error', 'message': '未指定配置文件'}), 400
        try:
            if not os.path.exists(config_file):
                return jsonify({'status': 'error', 'message': '配置文件不存在'}), 404
            with open(config_file, 'r') as f:
                content = f.read()
            return jsonify({'status': 'success', 'content': content, 'file': config_file})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    if request.method == 'POST':
        data = request.json
        content = data.get('content', '')
        if not config_file:
            return jsonify({'status': 'error', 'message': '未指定配置文件'}), 400
        try:
            # 创建备份
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            backup_path = f"{backup_dir}/{os.path.basename(config_file)}.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            if os.path.exists(config_file):
                shutil.copy(config_file, backup_path)
            
            # 保存新配置
            with open(config_file, 'w') as f:
                f.write(content)
            
            # 重启 OpenVPN 服务
            try:
                result = subprocess.run(
                    ['systemctl', 'restart', 'openvpn-server@server.service'],
                    capture_output=True, text=True, check=True
                )
                # 等待服务状态稳定
                time.sleep(2)
                status_result = subprocess.run(
                    ['systemctl', 'status', 'openvpn-server@server.service'],
                    capture_output=True, text=True
                )
                if 'Active: active (running)' in status_result.stdout:
                    return jsonify({'status': 'success', 'message': '配置保存并重启成功'})
                else:
                    error_message = 'OpenVPN 服务启动失败'
                    log_file = CONFIG['OPENVPN_LOG']
                    if os.path.exists(log_file):
                        with open(log_file, 'r') as f:
                            lines = f.readlines()
                            recent_errors = [line for line in lines[-50:] if 'ERROR' in line]
                            if recent_errors:
                                error_message += f'，最近错误日志：{recent_errors[-1].strip()}'
                    return jsonify({'status': 'error', 'message': error_message}), 500
            except subprocess.CalledProcessError as e:
                error_message = f'重启 OpenVPN 服务失败: {e.stderr}'
                return jsonify({'status': 'error', 'message': error_message}), 500
                
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'保存配置失败：{str(e)}'}), 500

# 列出日志文件
@app.route('/api/log_files', methods=['GET'])
@role_required('admin')
def list_log_files():
    try:
        log_files = glob.glob(f"{CONFIG['OPENVPN_LOG']}*")
        log_files.sort(key=os.path.getmtime, reverse=True)
        return jsonify({'status': 'success', 'files': log_files})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# 查看日志
@app.route('/api/logs', methods=['GET'])
@role_required('admin')
def view_logs():
    log_file = request.args.get('log_file', '')
    start_time = request.args.get('start_time', '')
    end_time = request.args.get('end_time', '')
    
    if not log_file:
        return jsonify({'status': 'error', 'message': '未指定日志文件'}), 400
    
    try:
        if not os.path.exists(log_file):
            return jsonify({'status': 'error', 'message': '日志文件不存在'}), 404
        
        logs = []
        start_ts = parse(start_time).timestamp() if start_time else None
        end_ts = parse(end_time).timestamp() if end_time else None
        
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    timestamp_str = line[:24] if line.startswith('[') else ''
                    if timestamp_str:
                        log_time = parse(timestamp_str[1:-1], fuzzy=True).timestamp()
                        if start_ts and log_time < start_ts:
                            continue
                        if end_ts and log_time > end_ts:
                            continue
                    logs.append(line)
                except (ValueError, TypeError):
                    logs.append(line)
                
        return jsonify({'status': 'success', 'logs': ''.join(logs)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# 用户连接状态
@app.route('/api/connections', methods=['GET'])
@role_required('admin')
def connections():
    try:
        connections, diagnostics = get_connection_info_from_logs()
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            for diag in diagnostics:
                f.write(f'{datetime.now()}: {diag}\n')
        return jsonify({'status': 'success', 'connections': connections})
    except Exception as e:
        with open(CONFIG['WEBUI_LOG_PATH'], 'a') as f:
            f.write(f'{datetime.now()}: Error in /api/connections: {str(e)}\n')
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    try:
        logging.info("开始初始化数据库...")
        print("开始初始化数据库...")
        init_db()
        logging.info("数据库初始化完成，开始启动 Flask 应用...")
        print("启动 Flask 应用...")
        app.run(host=CONFIG['FLASK_HOST'], port=CONFIG['FLASK_PORT'], debug=CONFIG['FLASK_DEBUG'])
    except Exception as e:
        error_msg = f"启动失败: {str(e)}"
        logging.error(error_msg)
        print(error_msg, file=sys.stderr)
        raise