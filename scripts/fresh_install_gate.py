from __future__ import annotations
import argparse, hashlib, os, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def run(argv:list[str],env:dict|None=None,cwd:Path=ROOT)->str:
    done=subprocess.run(argv,cwd=cwd,text=True,capture_output=True,env=env,check=False)
    print("$ "+subprocess.list2cmdline(argv)); print(done.stdout,end=""); print(done.stderr,end="",file=sys.stderr)
    if done.returncode: raise SystemExit(done.returncode)
    return done.stdout
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--wheel",type=Path,required=True); p.add_argument("--public-repo",default="https://github.com/octocat/Hello-World.git"); a=p.parse_args()
    root=ROOT/".provan-fresh-install"; shutil.rmtree(root,ignore_errors=True)
    state_parent=Path(tempfile.mkdtemp(prefix="provan-fresh-state-"))
    before_global=subprocess.run(["git","config","--global","--list"],text=True,capture_output=True).stdout
    try:
        run([sys.executable,"-m","venv",str(root)]); py=root/"Scripts/python.exe"; cli=root/"Scripts/provan.exe"
        run([str(py),"-m","pip","install","--no-deps",str(a.wheel.resolve())])
        env=dict(os.environ); env["PROVAN_HOME"]=str(state_parent/".provan")
        for args in (["--help"],["doctor","--format","json"],["telemetry","status"],["telemetry","schema"],["telemetry","preview"],["telemetry","enable"],["telemetry","preview"],["telemetry","reset-id"],["telemetry","disable"]): run([str(cli),*args],env,root)
        parity="""import os; from provan.telemetry import configure,preview,send; os.environ['PROVAN_TELEMETRY_ENDPOINT']='https://collector.example.test'; configure(True); p=preview(); seen=[]; send(p['envelope_digest'],lambda b,d:seen.append((b,d))); assert seen==[(p['canonical_bytes_utf8'].encode(),p['envelope_digest'])]; print('TRANSPORT_SPY_PARITY_OK')"""
        run([str(py),"-c",parity],env,root)
        remote_env=dict(os.environ); remote_env["GIT_TERMINAL_PROMPT"]="0"
        remote_commit=run(["git","ls-remote",a.public_repo,"HEAD"],remote_env,root).split()[0]
        receipt=Path(env["PROVAN_HOME"])/"outputs/public-inspection.json"; run([str(cli),"repository","inspect","--repo",a.public_repo,"--base",remote_commit,"--head",remote_commit,"--mode","source-only","--output",str(receipt)],env,root)
        installed=run([str(py),"-c","import provan,pathlib; print(pathlib.Path(provan.__file__).resolve())"],env,root).strip()
        if str(root/"Lib/site-packages").lower() not in installed.lower(): raise SystemExit("installed path escaped isolated environment")
        with zipfile.ZipFile(a.wheel) as z:
            if any(n.startswith(("shiproom/","demo_patient/","tests/","external_validation/")) for n in z.namelist()): raise SystemExit("forbidden wheel member")
        if any((root/"Lib/site-packages"/name).exists() for name in ("shiproom","demo_patient","external_validation")): raise SystemExit("forbidden installed package")
        run([str(py),"-m","pip","uninstall","-y","provan-assurance"],cwd=root)
        if (root/"Lib/site-packages/provan").exists(): raise SystemExit("uninstall residue")
        after_global=subprocess.run(["git","config","--global","--list"],text=True,capture_output=True).stdout
        if before_global!=after_global: raise SystemExit("global Git configuration changed")
        print("FRESH_INSTALL_GATE_OK"); return 0
    finally:
        shutil.rmtree(root,ignore_errors=True)
        shutil.rmtree(state_parent,ignore_errors=True)
if __name__=="__main__":raise SystemExit(main())
