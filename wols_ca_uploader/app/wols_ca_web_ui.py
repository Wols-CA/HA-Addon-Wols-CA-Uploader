from flask import Flask, request, render_template_string, redirect
import logging
import secrets_handler

app = Flask(__name__)

# Wols CA Dynamisch Design (Met Ingress-veilige relatieve URL's)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <title>Wols CA Dashboard</title>
    <style>
        body { font-family: Roboto, sans-serif; background-color: #1c1c1c; color: #e1e1e1; padding: 20px; }
        .card { background-color: #2b2b2b; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1, h2 { color: #03a9f4; margin-top: 0; }
        label { display: block; margin-top: 10px; font-weight: bold; color: #bbb; }
        input[type="text"], input[type="number"], select { width: 100%; padding: 10px; margin-top: 5px; background: #3c3c3c; border: 1px solid #555; color: white; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { margin-top: 15px; padding: 10px 20px; background-color: #03a9f4; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        input[type="submit"]:hover { background-color: #0288d1; }
        .success { color: #4caf50; font-weight: bold; margin-bottom: 15px; background: #1b3320; padding: 10px; border-radius: 4px; border: 1px solid #4caf50; }
        .flex-row { display: flex; gap: 15px; }
        .flex-col { flex: 1; }
        hr { border: 0; border-top: 1px solid #444; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Wols CA System Controller</h1>
    
    {% if message %}
        <div class="success">{{ message }}</div>
    {% endif %}

    <div class="flex-row">
        <div class="flex-col card">
            <h2>🌊 Sea Water Configuratie</h2>
            <form method="POST" action="update_system">
                <input type="hidden" name="sp_num" value="{{ sp_num }}">
                <label>Aantal actieve sensoren (Max 100):</label>
                <div style="display: flex; gap: 10px;">
                    <input type="number" name="sw_num" value="{{ sw_num }}" min="0" max="100">
                    <input type="submit" value="Opslaan">
                </div>
            </form>
            <hr>
            
            <form method="GET" action="">
                <input type="hidden" name="sp_id" value="{{ sp_id }}">
                <label>Selecteer Sensor ID om te bewerken:</label>
                <select name="sw_id" onchange="this.form.submit()">
                    {% for i in range(1, 101) %}
                        <option value="{{ i }}" {% if i|string == sw_id %}selected{% endif %}>Sensor ID {{ i }}</option>
                    {% endfor %}
                </select>
            </form>
            
            <form method="POST" action="update_seawater">
                <input type="hidden" name="sw_id" value="{{ sw_id }}">
                <input type="hidden" name="sp_id" value="{{ sp_id }}">
                <label>Positie {{ sw_id }} (Google Maps of Decimaal):</label>
                <input type="text" name="Position" value="{{ current_pos }}" placeholder="Bijv: 43°04'58.1&quot;N 6°03'56.2&quot;E">
                <input type="submit" value="Data Opslaan (ID {{ sw_id }})">
            </form>
        </div>

        <div class="flex-col card">
            <h2>🎵 Spotify Configuratie</h2>
            <form method="POST" action="update_system">
                <input type="hidden" name="sw_num" value="{{ sw_num }}">
                <label>Aantal actieve sets (Max 24):</label>
                <div style="display: flex; gap: 10px;">
                    <input type="number" name="sp_num" value="{{ sp_num }}" min="0" max="24">
                    <input type="submit" value="Opslaan">
                </div>
            </form>
            <hr>
            
            <form method="GET" action="">
                <input type="hidden" name="sw_id" value="{{ sw_id }}">
                <label>Selecteer Spotify Set ID om te bewerken:</label>
                <select name="sp_id" onchange="this.form.submit()">
                    {% for i in range(1, 25) %}
                        <option value="{{ i }}" {% if i|string == sp_id %}selected{% endif %}>Set ID {{ i }}</option>
                    {% endfor %}
                </select>
            </form>
            
            <form method="POST" action="update_spotify">
                <input type="hidden" name="sw_id" value="{{ sw_id }}">
                <input type="hidden" name="sp_id" value="{{ sp_id }}">
                <label>Bron Afspeellijst (Source ID {{ sp_id }}):</label>
                <input type="text" name="SourceID" value="{{ current_src }}">
                <label>Doel Afspeellijst (Target ID {{ sp_id }}):</label>
                <input type="text" name="TargetID" value="{{ current_tgt }}">
                <label>Afspeeltijd (PlayTime {{ sp_id }}):</label>
                <input type="text" name="PlayTime" value="{{ current_pt }}">
                <input type="submit" value="Data Opslaan (ID {{ sp_id }})">
            </form>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    sw_id = request.args.get('sw_id', '1')
    sp_id = request.args.get('sp_id', '1')

    sw_num = secrets_handler.get_secret("SeaWaterNumber") or "1"
    sp_num = secrets_handler.get_secret("PlaylistSets") or "1"

    current_pos = secrets_handler.get_secret(f"Position{sw_id}") or ""
    current_src = secrets_handler.get_secret(f"SourceID{sp_id}") or ""
    current_tgt = secrets_handler.get_secret(f"TargetID{sp_id}") or ""
    current_pt  = secrets_handler.get_secret(f"PlayTime{sp_id}") or ""
    
    return render_template_string(HTML_TEMPLATE, 
                                  sw_num=sw_num, sp_num=sp_num,
                                  sw_id=sw_id, sp_id=sp_id,
                                  current_pos=current_pos,
                                  current_src=current_src, current_tgt=current_tgt, current_pt=current_pt,
                                  message=request.args.get('msg'))

@app.route('/update_system', methods=['POST'])
def update_system():
    secrets_handler.update_secret("SeaWaterNumber", request.form.get('sw_num'))
    secrets_handler.update_secret("PlaylistSets", request.form.get('sp_num'))
    
    # WOLS CA FIX: Gebruik het veilige Ingress basis-pad voor de redirect
    base_url = request.headers.get('X-Ingress-Path', '')
    return redirect(f"{base_url}/?msg=✅ Wols CA Systeemaantallen succesvol bijgewerkt!")

@app.route('/update_seawater', methods=['POST'])
def update_seawater():
    sw_id = request.form.get('sw_id')
    sp_id = request.form.get('sp_id')
    secrets_handler.update_secret(f"Position{sw_id}", request.form.get('Position'))
    
    base_url = request.headers.get('X-Ingress-Path', '')
    return redirect(f"{base_url}/?sw_id={sw_id}&sp_id={sp_id}&msg=✅ Sea Water Positie {sw_id} opgeslagen!")

@app.route('/update_spotify', methods=['POST'])
def update_spotify():
    sw_id = request.form.get('sw_id')
    sp_id = request.form.get('sp_id')
    secrets_handler.update_secret(f"SourceID{sp_id}", request.form.get('SourceID'))
    secrets_handler.update_secret(f"TargetID{sp_id}", request.form.get('TargetID'))
    secrets_handler.update_secret(f"PlayTime{sp_id}", request.form.get('PlayTime'))
    
    base_url = request.headers.get('X-Ingress-Path', '')
    return redirect(f"{base_url}/?sw_id={sw_id}&sp_id={sp_id}&msg=✅ Spotify Set {sp_id} opgeslagen!")

def start_web_server():
    app.run(host='0.0.0.0', port=8099, debug=False, use_reloader=False)