from flask import Flask, request, jsonify, render_template
import subprocess
import tempfile
import os

app = Flask(__name__)


# ---------------- HOME ROUTE ----------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------- ANALYSIS ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        code = data.get("code", "")

        if not code.strip():
            return jsonify({
                "output": "No code provided.",
                "vulnerable": False,
                "severity": "NONE"
            })

        # Write code to temporary C file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as f:
            f.write(code.encode())
            temp_file = f.name

        # Run LLVM-based analysis engine
        result = subprocess.run(
            ["./taint_analysis", temp_file],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )

        # Remove temp file
        os.unlink(temp_file)

        output = result.stdout.strip() if result.stdout else ""

        # ---------- SEVERITY EXTRACTION (IMPORTANT FIX) ----------
        severity = "NONE"
        if "[SEVERITY] HIGH" in output:
            severity = "HIGH"
        elif "[SEVERITY] MEDIUM" in output:
            severity = "MEDIUM"

        vulnerable = "[VULNERABILITY]" in output

        if not output:
            output = "No vulnerabilities detected."

        return jsonify({
            "output": output,
            "vulnerable": vulnerable,
            "severity": severity
        })

    except Exception as e:
        return jsonify({
            "output": f"Backend error: {str(e)}",
            "vulnerable": False,
            "severity": "ERROR"
        }), 500


# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
