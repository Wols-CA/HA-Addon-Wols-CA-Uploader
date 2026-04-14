import logging
import json
from flask import Flask, request, redirect, url_for, render_template_string
import secrets_handler

app = Flask(__name__)
app.logger.setLevel(logging.ERROR)
mqtt_client_instance = None

TAB_INFO = {
    "SW_Status": "Sea Water Temperature",
    "SP_Status": "Spotify Playlists Status",
    "SW_Config": "Sea Water Config",
    "SP_Config": "Spotify Config"
}
BASE_TABS = list(TAB_INFO.keys())

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wols CA Control Center</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #f4f7f6; padding: 20px; }
        .header { display: flex; justify-content: space-between; border-bottom: 2px solid #0056b3; padding-bottom: 10px; margin-bottom: 20px; }
        .tab { display: flex; background: #e9ecef; border-radius: 5px 5px 0 0; }
        .tab button { flex: 1; padding: 14px; border: none; cursor: pointer; font-weight: bold; background: inherit; }
        .tab button.active { background: #fff; border-top: 3px solid #0056b3; }
        .tabcontent { display: none; padding: 20px; background: #fff; border: 1px solid #ccc; border-radius: 0 0 5px 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #f2f2f2; }
        .btn { background: #0056b3; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; }
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
    <div class="header"><h1>Wols CA Control Center</h1></div>
    <div class="tab">
        {% for tab_id in tab_order %}
        <button class="tablinks" id="btn_{{ tab_id }}" onclick="openTab(event, '{{ tab_id }}')">{{ tab_names[tab_id] }}</button>
        {% endfor %}
    </div>

    <div id="SW_Status" class="tabcontent">
        <h3>Actieve Sea Water Sensoren</h3>
        <table>
            <tr>
                <th>Sensor</th>
                <th>Coördinaten</th>
                <th>Berekende Locatie</th>
                <th>Laatste Temp.</th>
            </tr>
            {% for sensor in sw_data %}
            <tr>
                <td>Positie {{ sensor.id }}</td>
                <td><code>{{ sensor.pos }}</code></td>
                <td>{{ sensor.location or 'Zoeken...' }}</td>
                <td style="font-weight: bold; color: #0056b3;">
                    {{ sensor.temp if sensor.temp else '--' }} °C
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
    </body>
</html>
"""

def get_template_data():
    sw_count = int(secrets_handler.get_secret("SeaWaterNumber") or 0)
    sw_list = []
    for i in range(1, sw_count + 1):
        pos = secrets_handler.get_secret(f"Position{i}")
        state_raw = secrets_handler.get_secret(f"State_Position{i}")
        temp, loc = None, None
        if state_raw:
            try:
                js = json.loads(state_raw)
                temp = js.get("temp")
                loc = js.get("location")
            except: pass
        sw_list.append({"id": i, "pos": pos, "temp": temp, "location": loc})
    
    # Tab logica (verkort)
    order = (secrets_handler.get_secret("UI_TabOrder") or "SW_Status,SP_Status,SW_Config,SP_Config").split(",")
    return {"sw_data": sw_list, "tab_order": order, "tab_names": TAB_INFO, "default_tab": order[0]}

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML, **get_template_data())

def start_web_server():
    app.run(host='0.0.0.0', port=8099)