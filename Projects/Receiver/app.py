from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"message": "ping from {}".format(request.host)})

@app.route('/endpoint', methods=['POST'])
def receive_json():
    data = request.get_json()
    if data:
        print("Received JSON:", data)
        return jsonify({"status": "success", "received": data}), 200
    else:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
