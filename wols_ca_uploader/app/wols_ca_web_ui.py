import logging
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

# --- WOLS CA HTML TEMPLATE ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wols CA Control Center</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #0056b3; padding-bottom: 10px; }
        .header h1 { color: #0056b3; margin: 0; }
        
        .tab { overflow: hidden; background-color: #e9ecef; border-radius: 5px 5px 0 0; border: 1px solid #ccc; border-bottom: none; display: flex;}
        .tab button { flex: 1; background-color: inherit; border: none; outline: none; cursor: pointer; padding: 14px 20px; transition: 0.3s; font-size: 15px; font-weight: bold; color: #555; }
        .tab button:hover { background-color: #ddd; }
        .tab button.active { background-color: #fff; color: #0056b3; border-top: 3px solid #0056b3; }
        
        .tabcontent { display: none; padding: 20px; background: #fff; border: 1px solid #ccc; border-radius: 0 0 5px 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        
        .form-group { margin-bottom: 15px; background: #f9f9f9; padding: 15px; border-left: 4px solid #0056b3; border-radius: 3px; }
        .form-group h4 { margin-top: 0; color: #333; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #666; }
        input[type="text"], input[type="number"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; margin-bottom: 10px; font-family: monospace; }
        
        .btn { background-color: #0056b3; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; }
        .btn:hover { background-color: #004494; }
        
        .alert { padding: 10px; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px; margin-bottom: 20px; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        table, th, td { border: 1px solid #ddd; }
        th, td { padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        
        .ui-settings-bar { margin-top: 30px; padding: 15px; background: #e9ecef; border-radius: 4px; border: 1px solid #ced4da; font-size: 14px; display: flex; align-items: center; gap: 20px;}
        .ui-settings-bar select { padding: 5px; border-radius: 3px; border: 1px solid #ccc; font-weight: bold;}
    </style>
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            if(evt) { evt.currentTarget.className += " active"; }
            else { document.getElementById("btn_" + tabName).className += " active"; }
        }
        
        window.onload = function() {
            var defaultTab = "{{ default_tab }}";
            if (document.getElementById("btn_" + defaultTab)) {
                openTab(null, defaultTab);
            } else {
                openTab(null, "{{ tab_order[0] }}");
            }
        }
    </script>
</head>
<body>

    <div class="header">
        <h1>Wols CA Control Center</h1>
        <span>Status: <strong>Actief & Versleuteld</strong></span>
    </div>

    {% if msg %}
    <div class="alert">{{ msg }}</div>
    {% endif %}

    <div class="tab">
        {% for tab_id in tab_order %}
        <button class="tablinks" id="btn_{{ tab_id }}" onclick="openTab(event, '{{ tab_id }}')">{{ tab_names[tab_id] }}</button>
        {% endfor %}
    </div>

    {% macro ui_settings(current_tab_id) %}
    <div class="ui-settings-bar">
        <form action="/update_ui_prefs" method="POST" style="display: flex; gap: 20px; align-items: center; width: 100%; margin: 0;">
            <input type="hidden" name="source_tab" value="{{ current_tab_id }}">
            <div><strong>⚙️ Tabblad Instellingen:</strong></div>
            <div>
                <label style="display:inline; margin:0;">Zet op positie:</label>
                <select name="new_pos" onchange="this.form.submit()">
                    {% for i in range(4) %}
                    <option value="{{ i }}" {% if tab_order[i] == current_tab_id %}selected{% endif %}>{{ i + 1 }}</option>
                    {% endfor %}
                </select>
            </div>
            <div>
                <label style="cursor: pointer; display:flex; align-items:center; gap: 5px;">
                    <input type="radio" name="set_default" value="{{ current_tab_id }}" {% if default_tab == current_tab_id %}checked{% endif %} onchange="this.form.submit()">
                    Maak dit de Wols CA opstart-tab
                </label>
            </div>
            <noscript><button type="submit">Opslaan</button></noscript>
        </form>
    </div>
    {% endmacro %}

    <div id="SW_Status" class="tabcontent">
        <h3>Actieve Sea Water Sensoren</h3>
        <p>Overzicht van de sensoren die momenteel via MQTT gepusht worden naar de C++ Service.</p>
        <table>
            <tr><th>Sensor ID</th><th>GPS Coördinaten</th><th>Verwachte Node</th></tr>
            {% for pos in sw_positions %}
            <tr>
                <td>Positie {{ loop.index }}</td>
                <td><code>{{ pos }}</code></td>
                <td>Wols CA SeaWater System</td>
            </tr>
            {% endfor %}
            {% if not sw_positions %}
            <tr><td colspan="3">Geen posities geconfigureerd.</td></tr>
            {% endif %}
        </table>
        {{ ui_settings('SW_Status') }}
    </div>

    <div id="SP_Status" class="tabcontent">
        <h3>Actieve Spotify Playlists</h3>
        <p>Overzicht van de geplande afspeellijst-synchronisaties.</p>
        <table>
            <tr><th>Set ID</th><th>Bron (Source)</th><th>Doel (Target)</th><th>Afspeeltijd</th></tr>
            {% for sp in sp_sets %}
            <tr>
                <td>Set {{ loop.index }}</td>
                <td><code>{{ sp.source }}</code></td>
                <td><code>{{ sp.target }}</code></td>
                <td>{{ sp.time }} min</td>
            </tr>
            {% endfor %}
            {% if not sp_sets %}
            <tr><td colspan="4">Geen Spotify sets geconfigureerd.</td></tr>
            {% endif %}
        </table>
        {{ ui_settings('SP_Status') }}
    </div>

    <div id="SW_Config" class="tabcontent">
        <h3>Sea Water Sensor Configuration</h3>
        <form action="/update_sw_config" method="POST">
            <div class="form-group">
                <label>Aantal Actieve Posities (SeaWaterNumber):</label>
                <input type="number" name="SeaWaterNumber" value="{{ sw_count }}" min="0" max="100">
            </div>
            
            {% for i in range(1, sw_count + 1) %}
            <div class="form-group">
                <h4>Positie {{ i }}</h4>
                <label>Google Maps Coördinaten (bijv. 43.08279, 6.06561):</label>
                <input type="text" name="Position{{ i }}" value="{{ get_secret('Position' ~ i) or '' }}">
            </div>
            {% endfor %}
            
            <button type="submit" class="btn">Sla Zeewater Configuraties Op & Push naar C++</button>
        </form>
        {{ ui_settings('SW_Config') }}
    </div>

    <div id="SP_Config" class="tabcontent">
        <h3>Spotify Playlists Configuration</h3>
        <form action="/update_sp_config" method="POST">
            <div class="form-group">
                <label>Aantal Playlist Sets (PlaylistSets):</label>
                <input type="number" name="PlaylistSets" value="{{ sp_count }}" min="0" max="25">
            </div>
            
            {% for i in range(1, sp_count + 1) %}
            <div class="form-group">
                <h4>Playlist Set {{ i }}</h4>
                <label>Source ID (Originele Playlist):</label>
                <input type="text" name="SourceID{{ i }}" value="{{ get_secret('SourceID' ~ i) or '' }}">
                <label>Target ID (Doel Playlist):</label>
                <input type="text" name="TargetID{{ i }}" value="{{ get_secret('TargetID' ~ i) or '' }}">
                <label>PlayTime (Minuten):</label>
                <input type="number" name="PlayTime{{ i }}" value="{{ get_secret('PlayTime' ~ i) or '' }}">
            </div>
            {% endfor %}
            
            <button type="submit" class="btn">Sla Spotify Configuraties Op & Push naar C++</button>
        </form>
        {{ ui_settings('SP_Config') }}
    </div>

</body>
</html>
"""

def set_interface_params(client):
    global mqtt_client_instance
    mqtt_client_instance = client

def get_template_data():
    try: sw_count = int(secrets_handler.get_secret("SeaWaterNumber") or 0)
    except ValueError: sw_count = 0
    
    try: sp_count = int(secrets_handler.get_secret("PlaylistSets") or 0)
    except ValueError: sp_count = 0

    sw_positions = []
    for i in range(1, sw_count + 1):
        pos = secrets_handler.get_secret(f"Position{i}")
        if pos: sw_positions.append(pos)

    sp_sets = []
    for i in range(1, sp_count + 1):
        src = secrets_handler.get_secret(f"SourceID{i}")
        tgt = secrets_handler.get_secret(f"TargetID{i}")
        tm = secrets_handler.get_secret(f"PlayTime{i}")
        if src or tgt: sp_sets.append({"source": src, "target": tgt, "time": tm})

    saved_order = secrets_handler.get_secret("UI_TabOrder")
    if saved_order:
        tab_list = saved_order.split(",")
        tab_list = [t for t in tab_list if t in BASE_TABS]
        for t in BASE_TABS:
            if t not in tab_list: tab_list.append(t)
    else:
        tab_list = BASE_TABS.copy()

    default_tab = secrets_handler.get_secret("UI_DefaultTab")
    if not default_tab or default_tab not in BASE_TABS:
        default_tab = tab_list[0]

    return {
        "sw_count": sw_count,
        "sp_count": sp_count,
        "sw_positions": sw_positions,
        "sp_sets": sp_sets,
        "tab_order": tab_list,
        "default_tab": default_tab,
        "tab_names": TAB_INFO,
        "get_secret": secrets_handler.get_secret
    }

@app.route('/')
def dashboard():
    msg = request.args.get('msg', '')
    data = get_template_data()
    return render_template_string(DASHBOARD_HTML, msg=msg, **data)

@app.route('/update_ui_prefs', methods=['POST'])
def update_ui_prefs():
    source_tab = request.form.get("source_tab")
    new_pos_str = request.form.get("new_pos")
    set_default = request.form.get("set_default")
    
    if set_default in BASE_TABS:
        secrets_handler.update_secret("UI_DefaultTab", set_default)
    
    if source_tab in BASE_TABS and new_pos_str is not None:
        try:
            new_pos = int(new_pos_str)
            saved_order = secrets_handler.get_secret("UI_TabOrder")
            tab_list = saved_order.split(",") if saved_order else BASE_TABS.copy()
            
            tab_list = [t for t in tab_list if t in BASE_TABS]
            for t in BASE_TABS:
                if t not in tab_list: tab_list.append(t)
                
            old_pos = tab_list.index(source_tab)
            if old_pos != new_pos and 0 <= new_pos < len(tab_list):
                tab_list.pop(old_pos)
                tab_list.insert(new_pos, source_tab)
                secrets_handler.update_secret("UI_TabOrder", ",".join(tab_list))
                
        except ValueError:
            pass

    return redirect(url_for('dashboard'))

@app.route('/update_sw_config', methods=['POST'])
def update_sw_config():
    sw_num = request.form.get("SeaWaterNumber", "0")
    secrets_handler.update_secret("SeaWaterNumber", sw_num)
    try: count = int(sw_num)
    except ValueError: count = 0
    for i in range(1, count + 1):
        val = request.form.get(f"Position{i}", "")
        secrets_handler.update_secret(f"Position{i}", val)
        if mqtt_client_instance:
            topic = f"wols_ca_mqtt/mb/local/seawaterdetails/set/Position{i}"
            mqtt_client_instance.publish(topic, val, qos=1)
    return redirect(url_for('dashboard', msg="✅ Sea Water Configuratie opgeslagen en gepusht!"))

@app.route('/update_sp_config', methods=['POST'])
def update_sp_config():
    sp_num = request.form.get("PlaylistSets", "0")
    secrets_handler.update_secret("PlaylistSets", sp_num)
    try: count = int(sp_num)
    except ValueError: count = 0
    for i in range(1, count + 1):
        src = request.form.get(f"SourceID{i}", "")
        tgt = request.form.get(f"TargetID{i}", "")
        tm = request.form.get(f"PlayTime{i}", "")
        secrets_handler.update_secret(f"SourceID{i}", src)
        secrets_handler.update_secret(f"TargetID{i}", tgt)
        secrets_handler.update_secret(f"PlayTime{i}", tm)
        if mqtt_client_instance:
            topic = f"wols_ca_mqtt/mb/local/spotifydetails/set/PlayTime{i}"
            mqtt_client_instance.publish(topic, tm, qos=1)
    return redirect(url_for('dashboard', msg="✅ Spotify Configuratie opgeslagen en gepusht!"))

def start_web_server():
    logging.info("Starting Wols CA Ingress Web UI with Dynamic Reordering...")
    app.run(host='0.0.0.0', port=8099, debug=False, use_reloader=False)

if __name__ == "__main__":
    start_web_server()