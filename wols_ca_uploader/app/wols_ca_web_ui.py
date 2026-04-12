from flask import Flask, request, render_template_string
import logging
import secrets_handler

app = Flask(__name__)

# Een strak, modern (donker) Wols CA design
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <title>Wols CA Dashboard</title>
    <style>
        body { font-family: Roboto, sans-serif; background-color: #1c1c1c; color: #e1e1e1; padding: 20px; }
        .card { background-color: #2b2b2b; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1, h2 { color: #03a9f4; }
        label { display: block; margin-top: 10px; font-weight: bold; }
        input[type="text"] { width: 100%; padding: 10px; margin-top: 5px; background: #3c3c3c; border: 1px solid #555; color: white; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { margin-top: 15px; padding: 10px 20px; background-color: #03a9f4; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        input[type="submit"]:hover { background-color: #0288d1; }
        .success { color: #4caf50; font-weight: bold; margin-bottom: 15px; }
    </style>
</head>
<body>
    <h1>Wols CA System Controller</h1>
    
    {% if message %}
        <div class="success">{{ message }}</div>
    {% endif %}

    <div class="card">
        <h2>🌊 Sea Water Monitoring</h2>
        <form method="POST" action="/update_seawater">
            <label>Positie 1 (Kopieer direct vanuit Google Maps):</label>
            <input type="text" name="Position1" value="{{ pos1 }}" placeholder="Bijv: 43°04'58.1&quot;N 6°03'56.2&quot;E">
            <input type="submit" value="Opslaan & Verzenden">
        </form>
    </div>

    <div class="card">
        <h2>🎵 Spotify Controller</h2>
        <form method="POST" action="/update_spotify">
            <label>Afspeellijst 1 - Bron (Source ID):</label>
            <input type="text" name="SourceID1" value="{{ src1 }}">
            <label>Afspeellijst 1 - Doel (Target ID):</label>
            <input type="text" name="TargetID1" value="{{ tgt1 }}">
            <label>Afspeeltijd (PlayTime):</label>
            <input type="text" name="PlayTime1" value="{{ pt1 }}" placeholder="Bijv: 60">
            <input type="submit" value="Opslaan & Verzenden">
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    # Lees de huidige waarden uit de veilige kluis om ze in het formulier te tonen
    pos1 = secrets_handler.get_secret("Position1") or ""
    src1 = secrets_handler.get_secret("SourceID1") or ""
    tgt1 = secrets_handler.get_secret("TargetID1") or ""
    pt1  = secrets_handler.get_secret("PlayTime1") or ""
    
    return render_template_string(HTML_TEMPLATE, pos1=pos1, src1=src1, tgt1=tgt1, pt1=pt1, message=request.args.get('msg'))

@app.route('/update_seawater', methods=['POST'])
def update_seawater():
    pos1 = request.form.get('Position1')
    # Omdat we straks de Uploader logica aanroepen, zal die het filteren en doorsturen.
    # Voor nu slaan we het simpelweg op in de kluis:
    secrets_handler.update_secret("Position1", pos1)
    
    # Let op: Om dit écht door te sturen naar C++, moeten we hier straks 
    # een MQTT bericht publiceren. Dat koppelen we in de volgende stap!
    
    return render_template_string(HTML_TEMPLATE, pos1=pos1, message="✅ Sea Water positie opgeslagen!")

@app.route('/update_spotify', methods=['POST'])
def update_spotify():
    secrets_handler.update_secret("SourceID1", request.form.get('SourceID1'))
    secrets_handler.update_secret("TargetID1", request.form.get('TargetID1'))
    secrets_handler.update_secret("PlayTime1", request.form.get('PlayTime1'))
    return render_template_string(HTML_TEMPLATE, message="✅ Spotify instellingen opgeslagen!")

def start_web_server():
    # Luister op alle interfaces op poort 8099
    app.run(host='0.0.0.0', port=8099, debug=False, use_reloader=False)