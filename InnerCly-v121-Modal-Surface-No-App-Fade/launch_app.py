"""Launch InnerCly v121 locally and replace stale InnerCly servers safely."""
from __future__ import annotations
import json, os, socket, subprocess, sys, time, urllib.error, urllib.request, webbrowser, signal, shlex
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT_MIN, PORT_MAX = 5000, 5110
EXPECTED_BUILD = "v121"

def data_dir() -> Path:
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"]) / "InnerCly"
    elif os.getenv("XDG_DATA_HOME"):
        root = Path(os.getenv("XDG_DATA_HOME")) / "InnerCly"
    else:
        root = Path.home() / ".local" / "share" / "InnerCly"
    root.mkdir(parents=True, exist_ok=True)
    return root

def api_info(port: int):
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/api/build", timeout=0.55) as response:
            data=json.loads(response.read().decode("utf-8"))
            if data.get("service")=="InnerCly": return data
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError):
        pass
    return None

def api_build(port: int):
    data=api_info(port)
    return data.get("build", "unknown") if data else None

def local_cookie_configured(port: int) -> bool:
    data=api_info(port)
    return bool(data and data.get("mode")=="local-testing" and data.get("cookie_secure") is False)

def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        # On POSIX, allow rebinding after the old server's recently closed HTTP sockets
        # entered TIME_WAIT. This does not allow a second listener to take a live port.
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: sock.bind((HOST,port)); return True
        except OSError: return False

def detect_live_innercly():
    live=[]
    for port in range(PORT_MIN,PORT_MAX+1):
        build=api_build(port)
        if build: live.append((port,build))
    return live

def saved_port_path() -> Path: return data_dir() / "launcher_port.txt"

def choose_port() -> int:
    marker=saved_port_path()
    try:
        saved=int(marker.read_text(encoding="utf-8").strip())
        if PORT_MIN <= saved <= PORT_MAX:
            if port_is_free(saved):
                return saved
            # Session cookies are scoped to the exact host+port. Silently changing
            # ports can make a valid saved login appear to disappear on next launch.
            if api_build(saved) is None:
                raise RuntimeError(
                    f"InnerCly's saved address uses port {saved}, but another program is using it. "
                    "Close that program and restart InnerCly so your login stays on the same address."
                )
    except (OSError, ValueError):
        pass
    for port in range(PORT_MIN,PORT_MAX+1):
        if port_is_free(port): return port
    raise RuntimeError("No free local port was found between 5000 and 5110.")

def stop_old_server(port: int) -> bool:
    """Stop only a Uvicorn main:app process bound to a port already verified as InnerCly."""
    if api_build(port) is None:
        return True
    try:
        if os.name == "nt":
            # Inspect command lines and only stop the specific `uvicorn main:app --port N` server.
            ps_script = rf"""
$portNumber = {int(port)}
$targets = @(Get-CimInstance Win32_Process | Where-Object {{
  $_.ProcessId -ne $PID -and $_.CommandLine -and
  $_.CommandLine -match '(?i)(-m\s+uvicorn\s+main:app|uvicorn\.exe\s+main:app)' -and
  $_.CommandLine -match ('(?i)--port\s+' + $portNumber + '(\s|$)')
}})
if ($targets.Count -eq 0) {{ exit 3 }}
$targets | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}
exit 0
"""
            result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                                    capture_output=True, text=True, timeout=12)
            if result.returncode != 0:
                print("I couldn't safely stop the old InnerCly server automatically.")
                return False
        else:
            # Use process arguments, not a blind port kill. API identity was confirmed above.
            result = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True, timeout=5)
            targets=[]
            for line in result.stdout.splitlines():
                parts=line.strip().split(None,1)
                if len(parts)!=2: continue
                try: pid=int(parts[0])
                except ValueError: continue
                args=parts[1]
                if pid==os.getpid(): continue
                try: tokens=shlex.split(args)
                except ValueError: continue
                if not tokens: continue
                executable=Path(tokens[0]).name.lower()
                is_python_uvicorn=("python" in executable and "-m" in tokens and tokens.index("-m")+1 < len(tokens) and tokens[tokens.index("-m")+1] == "uvicorn" and "main:app" in tokens)
                is_uvicorn_entry=(executable.startswith("uvicorn") and "main:app" in tokens)
                try: port_arg=tokens.index("--port")
                except ValueError: port_arg=-1
                matches_port=port_arg>=0 and port_arg+1<len(tokens) and tokens[port_arg+1]==str(port)
                if (is_python_uvicorn or is_uvicorn_entry) and matches_port:
                    targets.append(pid)
            if not targets:
                print("I couldn't safely identify the old InnerCly Uvicorn process to stop.")
                return False
            for pid in targets:
                try: os.kill(pid, signal.SIGTERM)
                except ProcessLookupError: pass
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Could not replace old InnerCly server automatically: {exc}")
        return False
    deadline=time.monotonic()+9
    while time.monotonic()<deadline:
        if api_build(port) is None and port_is_free(port):
            return True
        time.sleep(0.2)
    print("The old InnerCly server did not release its port in time.")
    return False

def main() -> int:
    live=detect_live_innercly()
    current=next(((port,build) for port,build in live if build==EXPECTED_BUILD and local_cookie_configured(port)),None)
    if current:
        port=current[0]
        try: saved_port_path().write_text(str(port),encoding="utf-8")
        except OSError: pass
        url=f"http://{HOST}:{port}"
        fresh_url=f"{url}/?iclaunch=v121-{int(time.time())}"
        print(f"InnerCly v121 is already running at {url}. Opening a fresh page for this build.",flush=True)
        webbrowser.open(fresh_url,new=2)
        return 0
    if live:
        preferred=None
        try: preferred=int(saved_port_path().read_text(encoding="utf-8").strip())
        except (OSError, ValueError): pass
        target=next((entry for entry in live if entry[0]==preferred),None)
        if target is None:
            target=sorted(live,key=lambda item:(item[0],int(''.join(c for c in str(item[1]) if c.isdigit()) or 0)))[0]
        port, old_build = target
        print(f"Detected older InnerCly build {old_build} at http://{HOST}:{port}.")
        print("Replacing that InnerCly server while keeping the same local port and browser storage origin...",flush=True)
        if not stop_old_server(port):
            print("To continue manually: close the Command Prompt running the older InnerCly app, then run START_INNERCLY.bat again.")
            try: input("Press Enter to close this message. ")
            except EOFError: pass
            return 1
        print(f"Stopped the old server on port {port}. Starting v121 on that port.",flush=True)
    try: port=choose_port()
    except RuntimeError as exc: print(str(exc)); return 1
    try: saved_port_path().write_text(str(port),encoding="utf-8")
    except OSError: pass
    url=f"http://{HOST}:{port}"
    fresh_url=f"{url}/?iclaunch=v121-{int(time.time())}"
    env=os.environ.copy(); env["APP_ENV"]="development"
    custom_db=env.get("INNERCLY_DATABASE_URL","").strip()
    if custom_db: env["DATABASE_URL"]=custom_db
    else: env.pop("DATABASE_URL",None)
    command=[sys.executable,"-m","uvicorn","main:app","--host",HOST,"--port",str(port)]
    print("\n===============================================")
    print("InnerCly v121 — Create Flows Fixed")
    print("===============================================")
    print(f"Starting local app at {url}")
    print("Waiting for the server to confirm build v121...")
    print("Keep this terminal open. Press Ctrl+C to stop InnerCly.")
    print("===============================================\n",flush=True)
    proc=subprocess.Popen(command,cwd=BASE_DIR,env=env)
    deadline=time.monotonic()+45; opened=False
    try:
        while time.monotonic()<deadline:
            if proc.poll() is not None:
                print("The InnerCly server stopped before it became ready. Check the error above."); return int(proc.returncode or 1)
            if api_build(port)==EXPECTED_BUILD:
                print(f"Verified server build v121 — opening a fresh page at {url}",flush=True); webbrowser.open(fresh_url,new=2); opened=True; break
            time.sleep(0.35)
        if not opened:
            print("The server did not confirm build v121 within 45 seconds. No browser was opened.")
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
            return 1
        return proc.wait()
    except KeyboardInterrupt:
        print("\nStopping InnerCly..."); proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()
        return 0

if __name__ == "__main__": raise SystemExit(main())
