from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import os
import webbrowser
from threading import Timer

# Create Flask app
app = Flask(
    __name__,
    static_folder="static",  # Serve static files like styles.css from this folder
    template_folder="templates"  # Store HTML templates here
)
socketio = SocketIO(app)

# Get KRA ID dynamically based on the script directory or environment variable
script_dir = os.path.abspath(os.path.dirname(__file__))
KRA_ID = os.getenv("KRA_ID", os.path.basename(script_dir))  # Default: folder name

# Store logs in memory (this is not persistent)
logs = []

@app.route("/")
def index():
    """Render the main GUI page."""
    return render_template("index.html", kra_id=KRA_ID)

@socketio.on("connect")
def handle_connect():
    """Handle new client connections."""
    print(f"Client connected to {KRA_ID} GUI.")
    # Send existing logs to the newly connected client
    for log in logs:
        emit("log_update", log)

@socketio.on("new_log")
def handle_new_log(data):
    """
    Handle new log entries received via WebSocket.
    Expects `data` to be a string or JSON object with a `message` key.
    """
    if not isinstance(data, str) and "message" not in data:
        emit("log_error", {"error": "Invalid log format"})
        return
    
    log_message = data if isinstance(data, str) else data["message"]
    logs.append(log_message)  # Store the raw log message
    socketio.emit("log_update", log_message)  # Broadcast to all clients

def add_log_entry(log_message):
    """
    Add a log entry from the backend and broadcast it to connected clients.
    This function is useful for programmatically adding logs.
    """
    logs.append(log_message)
    socketio.emit("log_update", log_message)

if __name__ == "__main__":
    # Determine the dynamic port for the GUI
    default_port = 8003  # Default starting port
    kra_offset = int(KRA_ID[-1]) - 1 if KRA_ID[-1].isdigit() else 0
    port = int(os.getenv("GUI_PORT", default_port + kra_offset))

    # Automatically open the web browser if not suppressed
    auto_open_browser = os.getenv("AUTO_OPEN_BROWSER", "1") == "1"
    if auto_open_browser:
        url = f"http://localhost:{port}"
        Timer(1, lambda: webbrowser.open(url)).start()

    print(f"{KRA_ID} GUI running on http://0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)