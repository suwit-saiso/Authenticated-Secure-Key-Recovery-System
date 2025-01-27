from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import os
import webbrowser
from threading import Timer
from datetime import datetime

# Create Flask app
app = Flask(
    __name__,
    static_folder="static",  # Serve static files like styles.css from this folder
    template_folder="templates"  # Store HTML templates here
)
socketio = SocketIO(app)

# Store logs in memory (this is not persistent)
logs = []

@app.route("/")
def index():
    """Render the main GUI page."""
    return render_template("index.html")

@socketio.on("connect")
def handle_connect():
    """Handle new client connections."""
    print(f"Client connected to Sender GUI.")
    # Send existing logs to the newly connected client
    for log in logs:
        emit("log_update", log)

@app.route('/new_log', methods=['POST'])
def new_log():
    data = request.json
    if data and 'message' in data:
        log_message = {"message": data['message'], "timestamp": datetime.utcnow().isoformat()}
        logs.append(log_message)
        socketio.emit('log_update', log_message)
        return jsonify({'status': 'success'}), 200
    return jsonify({'status': 'error', 'message': 'Invalid payload'}), 400

def add_log_entry(log_message):
    """
    Add a log entry from the backend and broadcast it to connected clients.
    This function is useful for programmatically adding logs.
    """
    logs.append(log_message)
    socketio.emit("log_update", log_message)

if __name__ == "__main__":
    port = int(os.getenv("GUI_PORT", 8000))

    # Automatically open the web browser if not suppressed
    auto_open_browser = os.getenv("AUTO_OPEN_BROWSER", "1") == "1"
    if auto_open_browser:
        url = f"http://localhost:{port}"
        Timer(1, lambda: webbrowser.open(url)).start()

    print(f"Sender GUI running on http://0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)