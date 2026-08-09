from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def run(argv:list[str],env:dict|None=None,cwd:Path=ROOT)->str:
    done=subprocess.run(argv,cwd=cwd,text=True,capture_output=True,env=env,check=False)
    print("$ "+subprocess.list2cmdline(argv)); print(done.stdout,end=""); print(done.stderr,end="",file=sys.stderr)
    if done.returncode: raise SystemExit(done.returncode)
    return done.stdout
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--wheel",type=Path,required=True); p.add_argument("--public-repo",default="https://github.com/octocat/Hello-World.git"); a=p.parse_args()
    root=Path(tempfile.mkdtemp(prefix="provan-fresh-install-"))
    state_parent=Path(tempfile.mkdtemp(prefix="provan-fresh-state-"))
    before_global=subprocess.run(["git","config","--global","--list"],text=True,capture_output=True).stdout
    try:
        isolated_env=dict(os.environ)
        for inherited in ("PYTHONPATH","PYTHONHOME"):
            isolated_env.pop(inherited,None)
        isolated_env["PYTHONNOUSERSITE"]="1"
        run([sys.executable,"-m","venv",str(root)],isolated_env); py=root/"Scripts/python.exe"; cli=root/"Scripts/provan.exe"
        run([str(py),"-m","pip","install","--no-deps",str(a.wheel.resolve())],isolated_env)
        env=dict(isolated_env); env["PROVAN_HOME"]=str(state_parent/".provan")
        for args in (["--help"],["doctor","--format","json"],["telemetry","status"],["telemetry","schema"],["telemetry","preview"],["telemetry","enable"],["telemetry","preview"],["telemetry","reset-id"],["telemetry","disable"]): run([str(cli),*args],env,root)
        parity="""import os; from provan.telemetry import configure,preview,send; os.environ['PROVAN_TELEMETRY_ENDPOINT']='https://collector.example.test'; configure(True); p=preview(); seen=[]; send(p['envelope_digest'],lambda b,d:seen.append((b,d))); assert seen==[(p['canonical_bytes_utf8'].encode(),p['envelope_digest'])]; print('TRANSPORT_SPY_PARITY_OK')"""
        run([str(py),"-c",parity],env,root)
        remote_env=dict(os.environ); remote_env["GIT_TERMINAL_PROMPT"]="0"
        remote_commit=run(["git","ls-remote",a.public_repo,"HEAD"],remote_env,root).split()[0]
        receipt=Path(env["PROVAN_HOME"])/"outputs/public-inspection.json"; run([str(cli),"repository","inspect","--repo",a.public_repo,"--base",remote_commit,"--head",remote_commit,"--mode","source-only","--output",str(receipt)],env,root)
        fixture=root/"target";fixture.mkdir();run(["git","init"],cwd=fixture);run(["git","config","user.email","fresh@invalid"],cwd=fixture);run(["git","config","user.name","Fresh Gate"],cwd=fixture)
        (fixture/"app.py").write_text("VALUE = 1\n",encoding="utf-8");run(["git","add","app.py"],cwd=fixture);run(["git","commit","-m","base"],cwd=fixture);base=run(["git","rev-parse","HEAD"],cwd=fixture).strip()
        (fixture/"app.py").write_text("VALUE = 2\n",encoding="utf-8");(fixture/"schema.json").write_text('{"type":"object"}\n',encoding="utf-8");run(["git","add","."],cwd=fixture);run(["git","commit","-m","head"],cwd=fixture);head=run(["git","rev-parse","HEAD"],cwd=fixture).strip()
        literal=root/"literal-exists.txt";literal.write_text("file contents must not replace literal argument\n",encoding="utf-8")
        output=run([str(cli),"explain","--repo",str(fixture),"--base",base,"--head",head,"--brief",literal.name,"--user-journey","A user reviews the change","--no-model","--format","json"],env,root)
        brief=json.loads(output); assert brief["claims"]["source_attributed_product_intent"]==[literal.name] and brief["model_usage"]["calls"]==0
        brief_id=brief["brief_id"]
        for form in ("terminal","markdown","html"): run([str(cli),"explain","--repo",str(fixture),"--base",base,"--head",head,"--brief-file",str(literal),"--no-model","--format",form],env,root)
        run([str(cli),"explain","--repo",str(fixture),"--base",base,"--head",head,"--previous-brief",brief_id,"--no-model","--format","json"],env,root)
        run([str(cli),"acceptance","promote","--brief",brief_id],env,root)
        (fixture/"app.py").write_text("VALUE = 3\n",encoding="utf-8");(fixture/".env").write_text("TOKEN=NEVER_EXPOSE\n",encoding="utf-8")
        mutable=run([str(cli),"explain","--repo",str(fixture),"--working-tree","--no-model","--format","json"],env,root)
        if "NEVER_EXPOSE" in mutable: raise SystemExit("mutable sensitive content leaked")
        bad=fixture/"bad.txt";bad.write_bytes(b"\xff");done=subprocess.run([str(cli),"explain","--repo",str(fixture),"--working-tree","--brief-file",str(bad),"--no-model"],env=env,text=True,capture_output=True)
        if done.returncode!=2 or "INPUT_FILE_ENCODING_INVALID" not in done.stdout: raise SystemExit("safe-reader encoding failure missing")
        public_explain=run([str(cli),"explain","--repo",a.public_repo.removesuffix(".git"),"--base",remote_commit,"--head",remote_commit,"--brief","Review the bounded source change","--no-model","--format","json"],env,root)
        if json.loads(public_explain)["candidate"]["head"]!=remote_commit: raise SystemExit("public pinned explain mismatch")
        spy="""import json,os; import provan.modeling as m; from provan.modeling import ModelProvider,configure_provider; from provan.change_brief import explain; seen=[]; os.environ['PROVAN_MODEL_ALLOWLIST']='spy'; os.environ['PROVAN_MODEL_HOST_ALLOWLIST']='model.example.test'; m._wire_transport=lambda provider,raw,digest:(seen.append((json.loads(raw),digest)) or {'model_reviewed_implications':[],'cost_status':'reported'}); configure_provider(ModelProvider('spy','local','1','https://model.example.test/v1')); r=explain(repo=r'%s',base='%s',head='%s',working_tree=False,brief_text='bounded',agent_claim=None,context_files=[],aliases=[],journeys=[],journey_files=[],previous_brief=None,previous_manifest=None,provider_id='spy',no_model=False); assert len(seen)==1 and r['model_usage']['calls']==1 and r['model_usage']['latency_ms']>=0 and r['model_usage']['latency_source']=='provan_monotonic_elapsed' and seen[0][1]==r['model_usage']['envelope_digest']; print('MODEL_ENVELOPE_SPY_OK')"""%(fixture,base,head)
        run([str(py),"-c",spy],env,root)
        installed=run([str(py),"-c","import provan,pathlib; print(pathlib.Path(provan.__file__).resolve())"],env,root).strip()
        installed_path=Path(installed).resolve();site_packages=(root/"Lib/site-packages").resolve()
        try: installed_path.relative_to(site_packages)
        except ValueError: raise SystemExit("installed path escaped isolated environment")
        with zipfile.ZipFile(a.wheel) as z:
            names=z.namelist()
            if any(n.startswith(("shiproom/","demo_patient/","tests/","external_validation/")) for n in names): raise SystemExit("forbidden wheel member")
            if not any(n.endswith("provan/schemas/change-brief.v1.json") for n in names): raise SystemExit("Session 10 schemas absent from wheel")
        if any((root/"Lib/site-packages"/name).exists() for name in ("shiproom","demo_patient","external_validation")): raise SystemExit("forbidden installed package")
        run([str(py),"-m","pip","uninstall","-y","provan-assurance"],env,cwd=root)
        if (root/"Lib/site-packages/provan").exists(): raise SystemExit("uninstall residue")
        after_global=subprocess.run(["git","config","--global","--list"],text=True,capture_output=True).stdout
        if before_global!=after_global: raise SystemExit("global Git configuration changed")
        print("FRESH_INSTALL_GATE_OK"); return 0
    finally:
        shutil.rmtree(root,ignore_errors=True)
        shutil.rmtree(state_parent,ignore_errors=True)
if __name__=="__main__":raise SystemExit(main())
