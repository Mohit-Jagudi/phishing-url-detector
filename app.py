from flask import Flask, jsonify, render_template, request
from detector import analyze_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            result = analyze_url(url)
        except ValueError as exc:
            error = str(exc)
    return render_template("index.html", result=result, error=error)

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    try:
        return jsonify(analyze_url(url))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

if __name__ == "__main__":
    app.run(debug=True)
