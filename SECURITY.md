# Security Policy

## ⚠️ 重要な警告

このパッケージは `os._exit(1)` を使用してプロセスを強制終了します。

### 使用前に必ず理解してください

- **プロセスが即座に終了します**: 通常の終了処理（finally句、コンテキストマネージャ等）はスキップされます
- **再起動機構が必須です**: supervisord、systemd、Kubernetes等の自動再起動機構がない環境では使用しないでください
- **`self_destruct=False` がデフォルトです**: 明示的に有効化するまで自壊は発生しません
- **本番環境での使用は慎重に**: 誤検知によるサービス断のリスクがあります

### 推奨する使用環境

- supervisord による自動再起動が設定されている環境
- Kubernetes Pod として動作している環境
- 開発・検証環境でのテスト後、本番投入してください

### 脆弱性の報告

脆弱性を発見した場合は、GitHub Issues ではなく直接 [Issues](https://github.com/nanikore7250/vcd-python/issues) へご報告ください。
