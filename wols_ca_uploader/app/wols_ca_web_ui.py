import logging
import json
from flask import Flask, request, redirect, url_for, render_template_string
import secrets_handler

app = Flask(__name__)
app.logger.setLevel(logging.ERROR)
mqtt_client_instance = None

TAB_INFO = {
    "SW_Status": "Sea Water Insights",
    "SP_Status": "Spotify Operations",
    "SW_Config": "Sea Water Config",
    "SP_Config": "Spotify Config"
}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wols CA Control Center</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; padding: 20px; color: #333; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #004b87; padding-bottom: 10px; margin-bottom: 25px; }
        .header h1 { margin: 0; color: #004b87; font-size: 24px; }
        .header span { font-size: 14px; color: #666; font-weight: bold; }
        
        .tab { display: flex; background: #e9ecef; border-radius: 6px 6px 0 0; overflow: hidden; }
        .tab button { flex: 1; padding: 14px; border: none; cursor: pointer; font-weight: bold; background: inherit; color: #555; transition: 0.3s; }
        .tab button:hover { background: #dee2e6; }
        .tab button.active { background: #fff; border-top: 3px solid #004b87; color: #004b87; }
        
        .tabcontent { display: none; padding: 25px; background: #fff; border: 1px solid #ccc; border-top: none; border-radius: 0 0 6px 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 14px; border-bottom: 1px solid #eee; text-align: left; }
        th { background: #f8f9fa; color: #004b87; font-weight: 600; text-transform: uppercase; font-size: 13px; }
        tr:hover { background-color: #f1f4f8; }
        
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-active { background-color: #e3fcef; color: #0d8246; }
        .badge-pending { background-color: #fff3cd; color: #856404; }
        
        code { background: #f1f1f1; padding: 2px 6px; border-radius: 3px; font-family: monospace; color: #d63384; }
    </style>
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) { tabcontent[i].style.display = "none"; }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) { tablinks[i].className = tablinks[i].className.replace(" active", ""); }
            document.getElementById(tabName).style.display = "block";
            if(evt) evt.currentTarget.className += " active";
        }
        window.onload = function() { openTab(null, "{{ default_tab }}"); }
    </script>
</head>
<body>
    <div class="header">
        <h1>Wols CA IT Security NG</h1>
        <span>Secure Operations Dashboard</span>
    </div>
    
    <div class="tab">
        {% for tab_id in tab_order %}
        <button class="tablinks" id="btn_{{ tab_id }}" onclick="openTab(event, '{{ tab_id }}')">{{ tab_names[tab_id] }}</button>
        {% endfor %}
    </div>

    <div id="SW_Status" class="tabcontent">
        <h3>Active SeaWater Intelligence</h3>
        <p style="color: #666; font-size: 14px;">Data securely acquired via Ephemeral Mutual-RSA channels.</p>
        <table>
            <tr>
                <th>Status</th>
                <th>Sensor ID</th>
                <th>Configuration (Lat, Lon)</th>
                <th>Resolved Location</th>
                <th>Latest Temperature</th>
                <th>Last Update</th>
            </tr>
            {% for sensor in sw_data %}
            <tr>
                <td>
                    {% if sensor.temp %}
                        <span class="badge badge-active">ONLINE</span>
                    {% else %}
                        <span class="badge badge-pending">PENDING</span>
                    {% endif %}
                </td>
                <td><strong>Position {{ sensor.id }}</strong></td>
                <td><code>{{ sensor.pos }}</code></td>
                <td>{{ sensor.location or 'Awaiting Data...' }}</td>
                <td style="font-weight: bold; color: #004b87; font-size: 16px;">
                    {{ sensor.temp ~ ' °C' if sensor.temp else '--' }}
                </td>
                <td style="font-size: 12px; color: #888;">
                    {{ sensor.timestamp or '--' }}
                </td>
            </tr>
            {% else %}
            <tr><td colspan="6" style="text-align: center; color: #888;">No active sensors configured.</td></tr>
            {% endfor %}
        </table>
    </div>
    
    <div id="SP_Status" class="tabcontent">
        <h3>Spotify Operations</h3>
        <p>Operational data will appear here.</p>
    </div>
    <div id="SW_Config" class="tabcontent">
        <h3>SeaWater Configuration</h3>
        <p>Manage coordinates via Home Assistant UI.</p>
    </div>
    <div id="SP_Config" class="tabcontent">
        <h3>Spotify Configuration</h3>
        <p>Manage playlists via Home Assistant UI.</p>
    </div>
</body>
</html>
"""

def get_template_data():
    sw_count = int(secrets_handler.get_secret("SeaWaterNumber") or 0)
    sw_list = []
    
    for i in range(1, sw_count + 1):
        pos = secrets_handler.get_secret(f"Position{i}")
        if not pos: continue # Sla over als er geen configuratie is
            
        state_raw = secrets_handler.get_secret(f"State_Position{i}")
        temp, loc, ts = None, None, None
        
        if state_raw:
            try:
                js = json.loads(state_raw)
                temp = js.get("temperature")
                loc = js.get("location")
                ts = js.get("timestamp")
            except Exception: pass
            
        sw_list.append({
            "id": i, 
            "pos": pos, 
            "temp": temp, 
            "location": loc,
            "timestamp": ts
        })
    
    # Bepaal weergave volgorde
    order_str = secrets_handler.get_secret("UI_TabOrder") or "SW_Status,SP_Status,SW_Config,SP_Config"
    order = [t for t in order_str.split(",") if t in TAB_INFO]
    if not order: order = list(TAB_INFO.keys())
    
    return {
        "sw_data": sw_list, 
        "tab_order": order, 
        "tab_names": TAB_INFO, 
        "default_tab": order[0]
    }

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML, **get_template_data())

def set_interface_params(client):
    global mqtt_client_instance
    mqtt_client_instance = client

def start_web_server():
    app.run(host='0.0.0.0', port=8099)