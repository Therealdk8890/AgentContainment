"""Standalone AgentContainment enforcement daemon."""
from __future__ import annotations
import argparse, signal, threading
from .control import ContainmentService
from .transport import UnixControlServer

def main() -> int:
    parser = argparse.ArgumentParser(description="AgentContainment action enforcement daemon")
    parser.add_argument("--socket", default="/run/agentcontainment/control.sock")
    parser.add_argument("--socket-mode", default="0660")
    parser.add_argument("--allowed-uid", action="append", type=int)
    parser.add_argument("--privileged-uid", action="append", type=int)
    args = parser.parse_args()
    service = ContainmentService()
    server = UnixControlServer(service, args.socket, mode=int(args.socket_mode, 8), allowed_uids=set(args.allowed_uid) if args.allowed_uid else None, privileged_uids=set(args.privileged_uid) if args.privileged_uid else None)
    stop = threading.Event()
    def shutdown(_signum, _frame):
        stop.set()
        server.close()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.start()
    try: server.serve_forever(stop_event=stop)
    finally: server.close()
    return 0

if __name__ == "__main__": raise SystemExit(main())