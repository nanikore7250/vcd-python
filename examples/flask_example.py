"""
Flask + VCDMiddleware の使用例。

起動方法:
    pip install vcd-python[flask]
    python examples/flask_example.py

自壊を有効化する場合は supervisord 等を使用してください。
"""

from flask import Flask, request, jsonify
from vcd import VCDMiddleware
from vcd.detector import BaseDetector

app = Flask(__name__)


@app.route("/")
def index():
    return "Hello, World!"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": []})


@app.route("/login", methods=["POST"])
def login():
    return jsonify({"status": "ok"})


# カスタム検知器の例
class PathTraversalDetector(BaseDetector):
    def detect(self, req):
        if "../" in req.path or "..%2F" in req.path:
            return True, "path traversal detected"
        return False, ""


def on_attack_detected(req, reason):
    print(f"[VCD] Attack detected: {reason} from {req.remote_addr}")


# ミドルウェアを適用（自壊無効・デフォルト設定）
app.wsgi_app = VCDMiddleware(
    app.wsgi_app,
    self_destruct=True,          # 本番で有効化する場合は True に変更
    forensics_path="/tmp/vcd_forensics.jsonl",
    blocklist_path="/tmp/vcd_blocklist.txt",
    on_detect=on_attack_detected,
)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
