from __future__ import annotations
import json
import os
import subprocess
from .runner import docker_available, docker_executable, validate_docker_argv

def qualification() -> dict:
    if not docker_available(): return {"qualification_status":"IMPLEMENTED_BUT_RUNTIME_QUALIFICATION_BLOCKED","reason":"docker_linux_engine_unavailable","required_command":"python -m shiproom.external_validation.doctor"}
    docker = docker_executable(); image=os.environ.get("SHIPROOM_DOCKER_QUALIFICATION_IMAGE", "busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028")
    base=[docker,"run","--rm","--pull=never","--network=none","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges","--user","65532:65532","--cpus","1","--memory","128m","--memory-swap","128m","--pids-limit","64","--tmpfs","/tmp:rw,nosuid,nodev,noexec,size=16m",image]
    try:
        validate_docker_argv(base)
        canary_env = dict(os.environ, SHIPROOM_CANARY_SECRET="host-only-canary")
        readonly=subprocess.run(base+["sh","-c","touch /blocked"],capture_output=True,text=True,timeout=30,env=canary_env).returncode
        network=subprocess.run(base+["nslookup","example.com"],capture_output=True,text=True,timeout=30,env=canary_env).returncode
        secret=subprocess.run(base+["sh","-c","test -z \"$SHIPROOM_CANARY_SECRET\" && test ! -e /var/run/docker.sock"],capture_output=True,text=True,timeout=30,env=canary_env).returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"qualification_status":"QUALIFICATION_FAILED","reason":"docker_canary_execution_failed","detail":type(exc).__name__}
    if readonly != 0 and network != 0 and secret == 0:
        return {"qualification_status":"QUALIFIED","image":image,"canaries":{"read_only": "enforced", "network": "enforced", "secret_socket": "isolated"}}
    return {"qualification_status":"QUALIFICATION_FAILED","reason":"docker_policy_not_enforced","canary_codes":{"read_only":readonly,"network":network,"secret_socket":secret}}

def main() -> int:
    result = qualification()
    print(json.dumps(result, sort_keys=True)); return 0 if result["qualification_status"] == "QUALIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
