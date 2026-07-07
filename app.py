from flask import Flask, render_template, request
from detector import analyze_url
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

    return render_template(
        "index.html",
        result=result,
        error=error
    )
    
app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)
