import os


def self_destruct():
    """Terminate the process immediately, bypassing normal cleanup.
    Requires supervisord, systemd, or similar to restart the process.
    """
    os._exit(1)
