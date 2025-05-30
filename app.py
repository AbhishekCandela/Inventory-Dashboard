from flask import Flask, Response, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps
from flask import make_response
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import io

app = Flask(__name__)
app.secret_key = 'Qwertyuiop1234567890'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, role, is_approved, is_active):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self._is_approved = bool(is_approved)
        self._is_active = bool(is_active)

    @property
    def is_approved(self):
        return self._is_approved

    @property
    def is_active(self):
        return self._is_active

    def get_id(self):
        return str(self.id)


def init_db():
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        is_approved INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1
    )
''')

    c.execute('''
            CREATE TABLE IF NOT EXISTS devicedata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                devicename TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                device_type TEXT NOT NULL,
                model_name TEXT NOT NULL,
                model_version TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                wifi_mode TEXT NOT NULL,
                supported_bands TEXT NOT NULL,
                spatial_streams TEXT NOT NULL,
                max_phy_rate TEXT NOT NULL,
                chipset TEXT NOT NULL,
                os_version TEXT NOT NULL,
                bandwidth TEXT NOT NULL,
                region TEXT NOT NULL,
                purchase_date TEXT NOT NULL,
                model_year TEXT NOT NULL,
                features TEXT NOT NULL,
                condition TEXT NOT NULL,
                controlled_app TEXT NOT NULL,
                remarks TEXT NOT NULL,
                battery TEXT NOT NULL,
                connection TEXT NOT NULL,
                location TEXT NOT NULL
            )
        ''')
    # Default admin user
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, role, is_approved, is_active) VALUES (?, ?, ?, ?, ?)", ('admin', 'admin123', 'admin', 1, 1))
    conn.commit()
    conn.close()

@app.before_request
def require_login_for_protected_pages():
    protected_paths = ['/', '/settings', '/form', '/view_data', '/approve_user', '/toggle_access', '/delete_user', '/toggle_role']
    if request.path in protected_paths and not current_user.is_authenticated:
        return redirect(url_for('login'))

def no_cache(view):
    @wraps(view)
    def no_cache_wrapper(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_wrapper

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("SELECT id, username, password, role, is_approved, is_active FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(*user)
    return None

@app.route('/approve_user/<int:id>')
@login_required
@no_cache
def approve_user(id):
    if current_user.role != 'admin':
        flash("Unauthorized action")
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("UPDATE users SET is_approved = 1 WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('settings'))

@app.route('/toggle_access/<int:id>')
@login_required
@no_cache
def toggle_access(id):
    if current_user.role != 'admin':
        flash("Unauthorized action")
        return redirect(url_for('index'))

    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("SELECT is_active FROM users WHERE id = ?", (id,))
    status = c.fetchone()
    if status:
        new_status = 0 if status[0] else 1
        c.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, id))
    conn.commit()
    conn.close()
    return redirect(url_for('settings'))

@app.route('/delete_user/<int:id>')
@login_required
@no_cache
def delete_user(id):
    if current_user.role != 'admin':
        flash("Unauthorized action")
        return redirect(url_for('index'))

    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('settings'))

@app.route('/toggle_role/<int:id>')
@login_required
@no_cache
def toggle_role(id):
    if current_user.role != 'admin':
        flash("Unauthorized action")
        return redirect(url_for('index'))

    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (id,))
    role = c.fetchone()
    if role:
        new_role = 'user' if role[0] == 'admin' else 'admin'
        c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, id))
    conn.commit()
    conn.close()
    return redirect(url_for('settings'))

@app.route('/settings')
@login_required
@no_cache
def settings():
    if current_user.role != 'admin':
        flash("Unauthorized access")
        return redirect(url_for('index'))

    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()

    user_objs = [User(*u) for u in users]
    return render_template('settings.html', users=user_objs)

@app.route('/get_devices')
@no_cache
def get_devices():
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("SELECT DISTINCT devicename FROM device")
    devices = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify(devices)

@app.route('/index')
@no_cache
@login_required
def dashboard():
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM devicedata")
    total_devices = c.fetchone()[0]
    
    c.execute("""
    SELECT COUNT(*) FROM devicedata 
    WHERE purchase_date >= date('now', '-1 year')
""")
    recent_devices = c.fetchone()[0]
    percent_recent = (recent_devices / total_devices) * 100 if total_devices > 0 else 0
    
    c.execute("""
    SELECT wifi_mode, COUNT(*) as count 
    FROM devicedata 
    GROUP BY wifi_mode 
    ORDER BY count DESC LIMIT 1
""")
    most_common_wifi_mode = c.fetchone()
    most_common_wifi_mode = most_common_wifi_mode[0] if most_common_wifi_mode else "N/A"

    c.execute("SELECT COUNT(DISTINCT region) FROM devicedata")
    regions_count = c.fetchone()[0]

    
    c.execute("SELECT COUNT(DISTINCT device_type) FROM devicedata")
    device_types_count = c.fetchone()[0]
    
    conn.close()

    return render_template('graphs.html',total_devices=total_devices,device_types_count=device_types_count,regions_count=regions_count,user=current_user,percent_recent=percent_recent,most_common_wifi_mode=most_common_wifi_mode)

@app.route('/register', methods=['GET', 'POST'])
@no_cache
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = sqlite3.connect('devices.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role, is_approved, is_active) VALUES (?, ?, ?, ?, ?)",
                      (username, password, role, 0, 1))
            conn.commit()
            flash("Registered successfully. Waiting for admin approval.")
        except sqlite3.IntegrityError:
            flash("Username already exists.")
        conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@no_cache
def login():
    if current_user.is_authenticated:
            logout_user()
            session.clear()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = sqlite3.connect('devices.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ? AND role = ?", (username, password, role))
        user = c.fetchone()
        conn.close()

        if user:
            user_obj = User(*user)
            if not user_obj.is_approved:
                flash('Your account is awaiting admin approval.')
                return redirect(url_for('login'))
            if not user_obj.is_active:
                flash('Your account has been disabled.')
                return redirect(url_for('login'))
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials")
            return redirect(url_for('login'))

    return render_template('login.html')
@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
@no_cache
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/form', methods=['GET', 'POST'])
@login_required
@no_cache
def form():
    if request.method == 'POST':
        bands = ", ".join(sorted(request.form.getlist('supported_bands'))) if request.form.getlist('supported_bands') else "None"
        data_values = [
            request.form['devicename'],
            request.form['asset_id'],
            request.form['device_type'],
            request.form['model_name'],
            request.form['model_version'],
            request.form['mac_address'],
            request.form['wifi_mode'],
            bands,
            request.form['spatial_streams'],
            request.form['max_phy_rate'],
            request.form['chipset'],
            request.form['os_version'],
            request.form['bandwidth'],
            request.form['region'],
            request.form['purchase_date'],
            request.form['model_year'],
            request.form['features'],
            request.form['condition'],
            request.form['controlled_app'],
            request.form['remarks'],
            request.form['battery'],
            request.form['connection'],
            request.form['location']
        ]
        
        conn = sqlite3.connect('devices.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO devicedata (
                devicename, asset_id, device_type, model_name, model_version,
                mac_address, wifi_mode, supported_bands, spatial_streams,
                max_phy_rate, chipset, os_version, bandwidth, region,
                purchase_date, model_year, features, condition, controlled_app,
                remarks, battery, connection, location
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', data_values)
        conn.commit()
        conn.close()
        return redirect('/')
    
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    c.execute('SELECT * FROM devicedata')  # ✅ fixed
    devices = c.fetchall()
    conn.close()
    return render_template('form.html', devices=devices, user=current_user)


@app.route('/view_data')
@no_cache
def view_data():
    conn = sqlite3.connect('devices.db') 
    c = conn.cursor()
    c.execute("SELECT * FROM devicedata")
    rows = c.fetchall()
    conn.close()
    return render_template('view_data.html', rows=rows)

@app.route('/api/devices')
def get_device():
    conn = sqlite3.connect('devices.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devicedata")
    rows = c.fetchall()
    conn.close()
    data = [dict(row) for row in rows]
    return jsonify(data)
@app.route('/submit', methods=['POST'])
@login_required
@no_cache
def submit():
    if request.method == 'POST':
        bands = ", ".join(sorted(request.form.getlist('supported_bands'))) if request.form.getlist('supported_bands') else "None"
        data_values = [
            request.form['devicename'],
            request.form['asset_id'],
            request.form['device_type'],
            request.form['model_name'],
            request.form['model_version'],
            request.form['mac_address'],
            request.form['wifi_mode'],
            bands,
            request.form['spatial_streams'],
            request.form['max_phy_rate'],
            request.form['chipset'],
            request.form['os_version'],
            request.form['bandwidth'],
            request.form['region'],
            request.form['purchase_date'],
            request.form['model_year'],
            request.form['features'],
            request.form['condition'],
            request.form['controlled_app'],
            request.form['remarks'],
            request.form['battery'],
            request.form['connection'],
            request.form['location']
        ]

        conn = sqlite3.connect('devices.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO devicedata (
                devicename, asset_id, device_type, model_name, model_version,
                mac_address, wifi_mode, supported_bands, spatial_streams,
                max_phy_rate, chipset, os_version, bandwidth, region,
                purchase_date, model_year, features, condition, controlled_app,
                remarks, battery, connection, location
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', data_values)
        conn.commit()
        conn.close()

        return redirect('/index') 

@app.route('/index', methods=['GET', 'POST'])
@login_required
@no_cache
def index():
    return render_template("graphs.html", user=current_user)

@app.route('/export-csv')
def export_csv():
    # Connect to SQLite DB and read the table into a DataFrame
    conn = sqlite3.connect('devices.db')
    df = pd.read_sql_query("SELECT * FROM devicedata", conn)
    conn.close()

    # Set readable column names
    df.columns = [
        "ID", "Device_Name", "Asset_ID", "Device_Type", "Model_Name", "Model_Version",
        "MAC_Address", "WiFi_Mode", "Supported_Bands", "Spatial_Streams", "Max_PHY_Rate",
        "Chipset", "OS_Version", "Bandwidth", "Region", "Purchase_Date", "Model_Year",
        "Features", "Condition", "Controlled_App", "Remarks", "Battery", "Connection",
        "Location"
    ]

    # Convert DataFrame to CSV in memory
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)

    return Response(
        csv_buffer,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment; filename=device_inventory.csv"}
    )
@app.route('/export-excel')
def export_excel():
    # Connect to SQLite and read the table into a DataFrame
    conn = sqlite3.connect('devices.db')
    df = pd.read_sql_query("SELECT * FROM devicedata", conn)
    conn.close()

    # Rename columns
    df.columns = [
        "ID", "Device_Name", "Asset_ID", "Device_Type", "Model_Name", "Model_Version",
        "MAC_Address", "WiFi_Mode", "Supported_Bands", "Spatial_Streams", "Max_PHY_Rate",
        "Chipset", "OS_Version", "Bandwidth", "Region", "Purchase_Date", "Model_Year",
        "Features", "Condition", "Controlled_App", "Remarks", "Battery", "Connection",
        "Location"
    ]

    # Create an Excel file in memory
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='DeviceData')

    excel_buffer.seek(0)

    return Response(
        excel_buffer,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={"Content-Disposition": "attachment; filename=device_inventory.xlsx"}
    )


if __name__ == '__main__':
    init_db()
    app.run(port=5004, debug=True)
