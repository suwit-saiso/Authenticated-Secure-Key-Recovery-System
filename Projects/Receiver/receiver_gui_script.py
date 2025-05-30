from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import os
import webbrowser
from threading import Timer
from datetime import datetime
import requests

# Create Flask app
app = Flask(
    __name__,
    static_folder="static",  # Serve static files like styles.css from this folder
    template_folder="templates"  # Store HTML templates here
)
socketio = SocketIO(app)

# Update the receiver script URL
RECEIVER_SCRIPT_URL = "http://localhost:5050/manual_test"  # Adjust if necessary

# Store logs in memory (this is not persistent)
logs = []

@app.route("/")
def index():
    """Render the main GUI page."""
    return render_template("index.html")

@socketio.on("connect")
def handle_connect():
    """Handle new client connections."""
    print(f"Client connected to Receiver GUI.")
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

@app.route("/receiver_gui/recovery", methods=["POST"])
def handle_recovery():
    """
    Forward message to the receiver script.
    """
    data = request.json
    message = data.get("command")

    if not message:
        return jsonify({"status": "error", "message": "Message are required"}), 400

    try:
        # Forward data to sender_script.py
        payload = {"command": message}
        response = requests.post(RECEIVER_SCRIPT_URL, json=payload)
        
        if response.status_code == 200:
            log_message = {
                "message": f"Message sent to Receiver: {message}",
                "timestamp": datetime.utcnow().isoformat()
            }
            add_log_entry(log_message)  # Add log
            return jsonify({"status": "success", "response": response.json()}), 200
        else:
            error_message = response.json().get("error", "Unknown error")
            return jsonify({"status": "error", "message": error_message}), response.status_code
    except Exception as e:
        error_message = f"Failed to send message: {str(e)}"
        return jsonify({"status": "error", "message": error_message}), 500
    
@app.route("/receiver_gui/corrupt", methods=["POST"])
def handle_corrupt():
    """
    Forward the message to the receiver script.
    """
    data = request.json
    message = data.get("command")

    if not message:
        return jsonify({"status": "error", "message": "Message are required"}), 400

    try:
        # Forward data to sender_script.py
        payload = {"command": message}
        response = requests.post(RECEIVER_SCRIPT_URL, json=payload)
        
        if response.status_code == 200:
            log_message = {
                "message": f"Message sent to Receiver: {message}",
                "timestamp": datetime.utcnow().isoformat()
            }
            add_log_entry(log_message)  # Add log
            return jsonify({"status": "success", "response": response.json()}), 200
        else:
            error_message = response.json().get("error", "Unknown error")
            return jsonify({"status": "error", "message": error_message}), response.status_code
    except Exception as e:
        error_message = f"Failed to send message: {str(e)}"
        return jsonify({"status": "error", "message": error_message}), 500
    
def add_log_entry(log_message):
    """
    Add a log entry from the backend and broadcast it to connected clients.
    This function is useful for programmatically adding logs.
    """
    logs.append(log_message)
    socketio.emit("log_update", log_message)

if __name__ == "__main__":
    port = int(os.getenv("GUI_PORT", 8001))

    # Automatically open the web browser if not suppressed
    auto_open_browser = os.getenv("AUTO_OPEN_BROWSER", "1") == "1"
    if auto_open_browser:
        url = f"http://localhost:{port}"
        Timer(1, lambda: webbrowser.open(url)).start()

    print(f"Receiver GUI running on http://0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)