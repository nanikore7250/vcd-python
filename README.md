# vcd-python
[![PyPI](https://img.shields.io/pypi/v/vcd-python)](https://pypi.org/project/vcd-python/)

**Volatile Cyber Defense (VCD)** の Python 実装です。攻撃を検知したらプロセスが即座に証拠を保全して自壊し、クリーンな状態で回復するセキュリティミドルウェアです。

論文: [DOI: 10.5281/zenodo.19648507](https://zenodo.org/records/19648507)

## 対応している検知パターン（v0.1.0）

現バージョンは正規表現ベースの検知器を同梱しています。

| 検知器 | 検知対象の例 |
|--------|------------|
| `XSSDetector` | `<script>`, `onerror=`, `javascript:` 等 |
| `SQLiDetector` | `UNION SELECT`, `OR 1=1`, `--` 等 |

> **注意**: 正規表現ベースの検知は万能ではありません。「何をもって攻撃とみなすか」はシステムの要件に応じてカスタム検知器で補完してください。高度な攻撃パターンや文脈依存の検知には対応していません。

## インストール

```bash
pip install vcd-python
```

Flask と使用する場合:

```bash
pip install vcd-python[flask]
```

## クイックスタート

```python
from flask import Flask
from vcd import VCDMiddleware

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, World!"

# デフォルト：検知 → 証拠保全のみ（自壊・ブロックなし）
app.wsgi_app = VCDMiddleware(app.wsgi_app)
```

自壊を有効化する場合（本番推奨）:

```python
app.wsgi_app = VCDMiddleware(
    app.wsgi_app,
    self_destruct=True,
    forensics_path="/var/vcd/forensics.jsonl",
)
```

## ⚠️ 警告

`self_destruct=True` を設定すると、攻撃検知時にプロセスが `os._exit(1)` で即時終了します。
**supervisord・systemd・Kubernetes 等の自動再起動機構が必須です。**

詳細は [SECURITY.md](SECURITY.md) を参照してください。

## VCD の動作フロー

このプロダクトのコアは **証拠保全** と **自壊** です。

```
攻撃リクエスト
  ↓
検知（XSS・SQLi 等）
  ↓
証拠書き出し（forensics.jsonl へ）  ← コア
  ↓
自壊（os._exit(1)）                 ← コア
  ↓
supervisord 等による自動再起動
```

## IP ブロック機能（オプション）

デフォルトでは無効です。`block=True` を指定すると、攻撃元 IP を記録し、再起動後も同一 IP を 403 で遮断します。

```python
app.wsgi_app = VCDMiddleware(
    app.wsgi_app,
    self_destruct=True,
    forensics_path="/var/vcd/forensics.jsonl",
    block=True,
    blocklist_path="/var/vcd/blocklist.txt",
)
```

```
（再起動後）
  ↓
ブロックリスト読み込み → 同一 IP を 403 で遮断
```

## 設定オプション

| パラメータ | デフォルト | 説明 |
|---|---|---|
| `detectors` | `[XSSDetector(), SQLiDetector()]` | 使用する検知器のリスト |
| `self_destruct` | `False` | 自壊の有効化 |
| `forensics_path` | `/var/vcd/forensics.jsonl` | 証拠ファイルのパス |
| `block` | `False` | IP ブロック機能の有効化 |
| `blocklist_path` | `/var/vcd/blocklist.txt` | ブロックリストのパス（`block=True` 時に使用） |
| `on_detect` | `None` | 検知時のコールバック関数 |

## カスタム検知器

```python
from vcd import VCDMiddleware
from vcd.detector import BaseDetector

class MyDetector(BaseDetector):
    def detect(self, request):
        if "malicious" in request.get_data(as_text=True):
            return True, "custom pattern detected"
        return False, ""

app.wsgi_app = VCDMiddleware(
    app.wsgi_app,
    detectors=[MyDetector()],
    self_destruct=True,
)
```

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。
