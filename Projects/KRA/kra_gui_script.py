from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import os
import webbrowser
from threading import Timer

app = Flask(__name__)
socketio = SocketIO(app)

KRA_ID = os.getenv("KRA_ID", "kra1")  # Dynamic KRA ID

# Store logs in memory for simplicity
logs = []

@app.route("/")
def index():
    return render_template("index.html", kra_id=KRA_ID)

@socketio.on("connect")
def handle_connect():
    print(f"Client connected to {KRA_ID} GUI.")
    for log in logs:
        emit("log_update", log)

@socketio.on("new_log")
def handle_new_log(data):
    logs.append(data)
    socketio.emit("log_update", data)

def add_log_entry(log_message):
    """
    Add a log entry and broadcast it to connected clients.
    """
    log_entry = {"message": log_message}
    logs.append(log_entry)
    socketio.emit("log_update", log_entry)

if __name__ == "__main__":
    port = int(os.getenv("GUI_PORT", 8003 + int(KRA_ID[-1]) - 1))  # Dynamic port based on KRA ID
    # Automatically open the web browser after a slight delay
    url = f"http://localhost:{port}"
    Timer(1, lambda: webbrowser.open(url)).start()
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)