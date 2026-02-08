from flask import Flask, render_template, request, jsonify
from logic import analyze_password

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.json
    password = data.get('password', '')
    result = analyze_password(password)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)