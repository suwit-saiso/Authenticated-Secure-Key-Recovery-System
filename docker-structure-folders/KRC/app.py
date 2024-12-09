from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"message": "ping from {}".format(request.host)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
