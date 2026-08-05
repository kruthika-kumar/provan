from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/"artifacts/session9/transcripts"
def public_text(value:str)->str:
    value=value.replace(str(ROOT),"<COMMUNITY_WORKSPACE>").replace(str(ROOT).replace("\\","/"),"<COMMUNITY_WORKSPACE>")
    # Redact both ordinary paths and paths embedded in JSON output, where each
    # separator is escaped.  Stop at JSON/shell delimiters so surrounding
    # evidence remains intact and deterministic.
    value=re.sub(r'(?i)[A-Z]:(?:\\\\|\\)Users(?:(?:\\\\|\\)[^"\r\n,\]]+)+', "<USER_PATH>", value)
    return value.replace("\r\n","\n")
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--name"); p.add_argument("--normalize-existing",action="store_true"); p.add_argument("--timeout",type=int,default=2700); p.add_argument("command",nargs=argparse.REMAINDER); a=p.parse_args()
    if a.normalize_existing:
        for path in OUT.glob("*.public.txt"):
            content=public_text(path.read_text(encoding="utf-8")); path.write_text(content,encoding="utf-8",newline="\n")
            meta=path.with_suffix(".json")
            if meta.exists():
                value=json.loads(meta.read_text(encoding="utf-8")); value["transcript_hash"]="sha256:"+hashlib.sha256(content.encode()).hexdigest(); meta.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8",newline="\n")
        print("TRANSCRIPTS_NORMALIZED"); return 0
    if not a.name: raise SystemExit("--name required")
    command=a.command[1:] if a.command and a.command[0]=="--" else a.command
    if not command: raise SystemExit("command required")
    started_at=datetime.now(timezone.utc).isoformat()
    execution_commit=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
    execution_tree=subprocess.run(["git","rev-parse","HEAD^{tree}"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
    try:
        run=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,timeout=a.timeout,check=False)
        output=run.stdout+run.stderr; code=run.returncode; timed_out=False
    except subprocess.TimeoutExpired as exc:
        output=(exc.stdout or "")+(exc.stderr or ""); code=124; timed_out=True
    completed_at=datetime.now(timezone.utc).isoformat(); output=public_text(output)
    epoch=os.environ.get("SOURCE_DATE_EPOCH","NOT_SET"); pythonpath=os.environ.get("PYTHONPATH","NOT_SET")
    transcript=public_text("COMMAND: "+subprocess.list2cmdline(command)+"\nEXECUTION_COMMIT: "+execution_commit+"\nEXECUTION_TREE: "+execution_tree+"\nSTARTED_AT: "+started_at+"\nCOMPLETED_AT: "+completed_at+"\nSOURCE_DATE_EPOCH: "+epoch+"\nPYTHONPATH: "+pythonpath+"\nEXIT_CODE: "+str(code)+"\nTIMED_OUT: "+str(timed_out).lower()+"\n--- OUTPUT ---\n"+output)
    OUT.mkdir(parents=True,exist_ok=True); path=OUT/(a.name+".public.txt"); path.write_text(transcript,encoding="utf-8",newline="\n")
    digest="sha256:"+hashlib.sha256(transcript.encode()).hexdigest()
    metadata={"command":subprocess.list2cmdline(command),"execution_commit":execution_commit,"execution_tree":execution_tree,"started_at":started_at,"completed_at":completed_at,"environment":{"SOURCE_DATE_EPOCH":epoch,"PYTHONPATH":pythonpath},"exit_code":code,"timed_out":timed_out,"transcript_path":path.relative_to(ROOT).as_posix(),"transcript_hash":digest}
    (OUT/(a.name+".public.json")).write_text(json.dumps(metadata,sort_keys=True,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps(metadata)); return code
if __name__=="__main__":raise SystemExit(main())
