from flask import Flask, render_template, request, jsonify
from logic import analyze_password
import subprocess

app = Flask(__name__)

def get_last_modified():
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cd", "--date=format:%d/%m/%Y %H:%M"],
            capture_output=True, text=True
        )
        return result.stdout.strip() or "N/A"
    except Exception:
        return "N/A"

@app.route('/')
def index():
    last_modified = get_last_modified()
    return render_template('index.html', last_modified=last_modified)

@app.route('/check', methods=['POST'])
def check():
    data = request.json
    password = data.get('password', '')
    result = analyze_password(password)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
