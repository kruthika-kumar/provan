from __future__ import annotations

import hashlib
import ast
import configparser
import json
import os
import re
import shutil
import stat
import subprocess
import struct
import tempfile
import time
import tomllib
import uuid
import urllib.error
import urllib.request
import zlib
from importlib.resources import files
from pathlib import Path
from typing import Any, Protocol

from .canonical import canonical_bytes, sha256_bytes
from .errors import ProvanError
from .modeling import build_envelope, invoke, selected_provider, zero_usage
from .safe_input import read_bounded_file
from .session10_validators import validate_acceptance_preparation_serialized, validate_acceptance_seed_serialized, validate_cache_fragment_serialized, validate_change_brief_serialized, validate_context_bundle_serialized, validate_context_request_serialized, validate_manifest_serialized, validate_model_envelope_serialized, validate_model_usage_serialized, validate_previous_export_manifest_serialized, validate_promotion_serialized, validate_provider_result_serialized, validate_public_projection_serialized, validate_public_render_text, validate_topology_serialized
from .state import secure_read, secure_write, state_root
from .structural import StructuralValidationError,validate_schema_instance

FULL_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
SAFE_REMOTE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?")
SENSITIVE = re.compile(r"(?:^|/)(?:\.env(?:\..*)?|\.netrc|\.git-credentials|\.npmrc|\.pypirc|kubeconfig|config\.json|service-account(?:\.[^.]+)?\.json|application_default_credentials\.json|id_(?:rsa|dsa|ecdsa|ed25519)|credentials?(?:\..*)?|secrets?(?:\..*)?|.*\.(?:pem|p12|pfx|key))$", re.I)
GENERATED = re.compile(r"(?:^|/)(?:dist|build|node_modules|\.venv|venv|__pycache__)(?:/|$)")
MAX_CHANGED_FILES = 4096
MAX_ANALYSIS_BYTES = 8 * 1024 * 1024
MAX_ENTITY_DETAILS = 256
MAX_SNAPSHOT_FILES = 10000
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_REMOTE_STORAGE_BYTES = 128 * 1024 * 1024
MAX_REMOTE_FILES = 20000
MAX_REMOTE_REQUESTS = 16
POLICY_ID = "community.default.v1"
POLICY_VERSION = "1"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProvanError("PR_METADATA_REDIRECT_FORBIDDEN", "PR metadata redirects are forbidden")


def _schema_validate(filename: str,value: dict[str,Any]) -> None:
    schema=json.loads(files("provan.schemas").joinpath(filename).read_text(encoding="utf-8"))
    try:validate_schema_instance(value,schema)
    except StructuralValidationError as exc:raise ProvanError("CONTRACT_STRUCTURE_INVALID",f"{filename} failed {exc.keyword} at {list(exc.path)}") from exc


def resolve_pr_metadata(repository: str, pr: str, base: str, head: str) -> dict[str,Any]:
    if not SAFE_REMOTE.fullmatch(repository): raise ProvanError("PR_METADATA_HOST_FORBIDDEN","PR metadata requires canonical GitHub HTTPS")
    match=re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?",repository)
    assert match
    if pr.isdigit(): number=int(pr)
    else:
        parsed=re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([0-9]+)",pr)
        if not parsed or parsed.group(1,2)!=match.group(1,2): raise ProvanError("PR_METADATA_IDENTITY_MISMATCH","PR URL does not match repository")
        number=int(parsed.group(3))
    if number<1: raise ProvanError("PR_METADATA_IDENTITY_MISMATCH","PR number must be positive")
    url=f"https://api.github.com/repos/{match.group(1)}/{match.group(2)}/pulls/{number}"
    request=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","User-Agent":"provan-assurance/0.5.1"})
    try:
        # An explicit empty proxy map prevents urllib from inheriting proxy
        # endpoints or credentials from the host environment or OS settings.
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect).open(request,timeout=10) as response:
            if response.geturl()!=url: raise ProvanError("PR_METADATA_REDIRECT_FORBIDDEN","PR metadata endpoint changed")
            raw=response.read(512*1024+1)
    except urllib.error.URLError as exc: raise ProvanError("PR_METADATA_UNAVAILABLE","bounded credential-free PR metadata request failed") from exc
    if len(raw)>512*1024: raise ProvanError("PR_METADATA_TOO_LARGE","PR metadata exceeds 512 KiB")
    value=json.loads(raw)
    if value.get("base",{}).get("sha")!=base or value.get("head",{}).get("sha")!=head: raise ProvanError("PR_METADATA_COMMIT_MISMATCH","PR metadata does not match explicit base/head")
    return {"number":number,"html_url":f"https://github.com/{match.group(1)}/{match.group(2)}/pull/{number}","title":str(value.get("title") or ""),"body":str(value.get("body") or ""),"base":base,"head":head,"authority":"source_attributed_product_intent"}


def _git_env(home: Path) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "USERPROFILE": str(home),
           "XDG_CONFIG_HOME": str(home / "xdg"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_LFS_SKIP_SMUDGE": "1",
           "GIT_EXTERNAL_DIFF": "", "GIT_DIFF_OPTS": "--no-ext-diff"}
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC"):
        if os.environ.get(name): env[name] = os.environ[name]
    return env


def _git(repo: Path, args: list[str], *, timeout: int = 60, input_bytes: bytes | None = None,
         allowed_returncodes: tuple[int, ...] = (0,)) -> bytes:
    with tempfile.TemporaryDirectory(prefix="provan-git-home-") as temp:
        home = Path(temp); (home / "hooks").mkdir()
        command = ["git", "-c", f"core.hooksPath={home / 'hooks'}", "-c", f"core.excludesFile={os.devnull}",
                   "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "submodule.recurse=false",
                   "-c", "diff.external=", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.clean=", "-c", "filter.lfs.required=false",
                   "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never", *args]
        done = subprocess.run(command, cwd=repo, env=_git_env(home), input=input_bytes, capture_output=True,
                              timeout=timeout, check=False)
    if done.returncode not in allowed_returncodes:
        raise ProvanError("SOURCE_ONLY_GIT_OPERATION_FAILED", done.stderr.decode("utf-8", "replace")[:300])
    return done.stdout


def _bounded_remote_fetch(repo: Path, args: list[str], *, timeout: int = 120) -> bytes:
    """Run the single allowlisted fetch with live time, request, file, and storage bounds."""
    with tempfile.TemporaryDirectory(prefix="provan-git-home-") as temp:
        home=Path(temp);(home/"hooks").mkdir();trace=home/"curl.trace"
        command=["git","-c",f"core.hooksPath={home/'hooks'}","-c",f"core.excludesFile={os.devnull}","-c","protocol.ext.allow=never","-c","protocol.file.allow=never","-c","http.followRedirects=false","-c","http.maxRequests=1","-c","http.lowSpeedLimit=1024","-c","http.lowSpeedTime=15",*args]
        env=_git_env(home);env["GIT_TRACE_CURL"]=str(trace);env["GIT_TRACE_CURL_NO_DATA"]="1"
        process=subprocess.Popen(command,cwd=repo,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        started=time.monotonic()
        while process.poll() is None:
            count=0;size=0
            for path in repo.rglob("*"):
                try:
                    if path.is_file():count+=1;size+=path.stat().st_size
                except OSError:continue
            request_count=0
            if trace.exists():
                request_count=trace.read_text(encoding="utf-8",errors="replace").count("=> Send header,")
            if count>MAX_REMOTE_FILES or size>MAX_REMOTE_STORAGE_BYTES or request_count>MAX_REMOTE_REQUESTS:
                process.kill();process.communicate();raise ProvanError("REMOTE_FETCH_BOUND_EXCEEDED","remote fetch exceeded file, storage, or request bound")
            if time.monotonic()-started>timeout:
                process.kill();process.communicate();raise ProvanError("REMOTE_FETCH_TIMEOUT","remote fetch exceeded the time bound")
            time.sleep(0.05)
        stdout,stderr=process.communicate()
        count=0;size=0
        for path in repo.rglob("*"):
            try:
                if path.is_file():count+=1;size+=path.stat().st_size
            except OSError:continue
        request_count=trace.read_text(encoding="utf-8",errors="replace").count("=> Send header,") if trace.exists() else 0
        if count>MAX_REMOTE_FILES or size>MAX_REMOTE_STORAGE_BYTES or request_count>MAX_REMOTE_REQUESTS:
            raise ProvanError("REMOTE_FETCH_BOUND_EXCEEDED","completed remote fetch exceeded file, storage, or request bound")
    if process.returncode:raise ProvanError("SOURCE_ONLY_GIT_OPERATION_FAILED",stderr.decode("utf-8","replace")[:300])
    return stdout


def _loose_object(git_dir: Path, oid: str) -> tuple[str,bytes]:
    path=git_dir/"objects"/oid[:2]/oid[2:]
    if not path.is_file():raise ProvanError("MUTABLE_PACKED_OBJECT_STORE_UNSUPPORTED","mutable inspection requires bounded loose current objects")
    try:raw=zlib.decompress(path.read_bytes());header,body=raw.split(b"\0",1);kind,size=header.decode("ascii").split(" ",1)
    except Exception as exc:raise ProvanError("LOCAL_REPOSITORY_INVALID","loose Git object is malformed") from exc
    if int(size)!=len(body):raise ProvanError("LOCAL_REPOSITORY_INVALID","loose Git object size mismatch")
    return kind,body


def _head_oid(git_dir: Path) -> str:
    text=(git_dir/"HEAD").read_text(encoding="ascii",errors="strict").strip()
    if re.fullmatch(r"[0-9a-f]{40}",text):return text
    if not text.startswith("ref: "):raise ProvanError("LOCAL_REPOSITORY_INVALID","HEAD is not resolvable")
    ref=text[5:];path=git_dir/ref
    if path.is_file():return path.read_text(encoding="ascii",errors="strict").strip()
    packed=git_dir/"packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="ascii",errors="strict").splitlines():
            if line and not line.startswith(("#","^")):
                oid,name=line.split(" ",1)
                if name==ref:return oid
    raise ProvanError("LOCAL_REPOSITORY_INVALID","HEAD ref is unresolved")


def _head_tree_inventory(git_dir: Path) -> tuple[str,set[str],dict[str,str]]:
    head=_head_oid(git_dir);kind,commit=_loose_object(git_dir,head)
    if kind!="commit":raise ProvanError("LOCAL_REPOSITORY_INVALID","HEAD does not name a commit")
    first=commit.splitlines()[0].decode("ascii",errors="strict")
    if not first.startswith("tree "):raise ProvanError("LOCAL_REPOSITORY_INVALID","HEAD commit lacks tree")
    tree_ids:set[str]=set();blobs:dict[str,str]={}
    def walk(oid: str,prefix: str="") -> None:
        kind,body=_loose_object(git_dir,oid)
        if kind!="tree":raise ProvanError("LOCAL_REPOSITORY_INVALID","tree reference is invalid")
        tree_ids.add(oid);offset=0
        while offset<len(body):
            end=body.index(b"\0",offset);mode_name=body[offset:end];mode,name=mode_name.split(b" ",1);child=body[end+1:end+21].hex();offset=end+21
            relative=prefix+name.decode("utf-8","surrogateescape")
            if mode in {b"40000",b"040000"}:walk(child,relative+"/")
            else:blobs[relative]=child
    root=first[5:45];walk(root);return head,tree_ids,blobs


def _index_inventory(git_dir: Path) -> dict[str,str]:
    raw=(git_dir/"index").read_bytes();
    if len(raw)<12 or raw[:4]!=b"DIRC":raise ProvanError("LOCAL_REPOSITORY_INVALID","Git index is malformed")
    version,count=struct.unpack(">II",raw[4:12])
    if version not in {2,3}:raise ProvanError("MUTABLE_INDEX_VERSION_UNSUPPORTED","mutable inspection supports Git index v2/v3")
    offset=12;entries={}
    for _ in range(count):
        start=offset
        if offset+62>len(raw):raise ProvanError("LOCAL_REPOSITORY_INVALID","Git index entry is truncated")
        oid=raw[offset+40:offset+60].hex();flags=struct.unpack(">H",raw[offset+60:offset+62])[0];offset+=62
        if version==3 and flags&0x4000:offset+=2
        end=raw.index(b"\0",offset);path=raw[offset:end].decode("utf-8","surrogateescape");entries[path]=oid
        offset=end+1
        while (offset-start)%8:offset+=1
    return entries


def _copy_mutable_git_metadata(git_dir: Path, destination: Path) -> None:
    head,trees,head_blobs=_head_tree_inventory(git_dir);index_blobs=_index_inventory(git_dir)
    shutil.copytree(git_dir,destination,ignore=shutil.ignore_patterns("objects","hooks"),symlinks=False)
    (destination/"objects").mkdir(parents=True,exist_ok=True)
    required={head,*trees}
    required.update(oid for path,oid in head_blobs.items() if not SENSITIVE.search(path))
    required.update(oid for path,oid in index_blobs.items() if not SENSITIVE.search(path))
    for oid in sorted(required):
        source=git_dir/"objects"/oid[:2]/oid[2:];target=destination/"objects"/oid[:2]/oid[2:]
        if not source.is_file():raise ProvanError("MUTABLE_PACKED_OBJECT_STORE_UNSUPPORTED","mutable inspection requires bounded loose current objects")
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)


def _repo_fingerprint(repo: Path) -> dict[str, str]:
    values = {}
    for label, args in (("head", ["rev-parse", "HEAD"]), ("refs", ["show-ref", "--head"])):
        values[label] = sha256_bytes(_git(repo, args))
    index = repo / ".git" / "index"
    values["index"] = sha256_bytes(index.read_bytes() if index.is_file() else b"")
    objects = repo / ".git" / "objects"
    for name in ("alternates","http-alternates"):
        alternate=objects/"info"/name
        if alternate.exists():raise ProvanError("UNSAFE_GIT_ALTERNATES_FORBIDDEN","repository object alternates are not inspected")
    inventory = []
    if objects.is_dir():
        for path in sorted(objects.rglob("*")):
            info=path.lstat()
            if stat.S_ISLNK(info.st_mode) or (os.name=="nt" and bool(getattr(info,"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT)):raise ProvanError("UNSAFE_GIT_OBJECT_LINK_FORBIDDEN","linked Git object storage is not inspected")
            if stat.S_ISREG(info.st_mode): inventory.append((path.relative_to(objects).as_posix(), info.st_size))
    values["objects"] = sha256_bytes(canonical_bytes(inventory))
    values["status"] = sha256_bytes(_git(repo,["status","--porcelain=v2","-z","--untracked-files=all"]))
    worktree=[]
    for directory,dirnames,filenames in os.walk(repo,followlinks=False):
        current=Path(directory)
        if current==repo:dirnames[:]=[name for name in dirnames if name!=".git"]
        for name in sorted(dirnames+filenames):
            path=current/name;info=path.lstat();worktree.append((path.relative_to(repo).as_posix(),info.st_size,info.st_mtime_ns,stat.S_IFMT(info.st_mode)))
            if len(worktree)>10000:raise ProvanError("TARGET_INVENTORY_LIMIT_EXCEEDED","bounded target immutability inventory exceeded")
    values["worktree"] = sha256_bytes(canonical_bytes(worktree))
    return values


def _target_fingerprint(repo: Path) -> dict[str,str]:
    git_dir=repo/".git"
    if not git_dir.is_dir() or git_dir.is_symlink():raise ProvanError("LOCAL_REPOSITORY_INVALID","local repository must have a non-linked .git directory")
    rows=[];count=0;total=0
    for root in (git_dir/"refs",git_dir/"objects"):
        if not root.exists():continue
        for path in sorted(root.rglob("*")):
            info=path.lstat()
            if stat.S_ISLNK(info.st_mode) or (os.name=="nt" and bool(getattr(info,"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT)):raise ProvanError("UNSAFE_GIT_OBJECT_LINK_FORBIDDEN","linked Git metadata is not inspected")
            if stat.S_ISREG(info.st_mode):
                count+=1;total+=info.st_size
                if count>MAX_SNAPSHOT_FILES or total>512*1024*1024:raise ProvanError("TARGET_INVENTORY_LIMIT_EXCEEDED","bounded target Git inventory exceeded")
                digest=hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda:handle.read(1024*1024),b""):digest.update(chunk)
                rows.append((path.relative_to(git_dir).as_posix(),info.st_size,digest.hexdigest()))
    fixed={name:sha256_bytes((git_dir/name).read_bytes() if (git_dir/name).is_file() else b"") for name in ("HEAD","index","packed-refs")}
    work=[]
    for directory,dirnames,filenames in os.walk(repo,followlinks=False):
        current=Path(directory)
        if current==repo:dirnames[:]=[name for name in dirnames if name!=".git"]
        for name in sorted(dirnames+filenames):
            path=current/name;info=path.lstat();relative=path.relative_to(repo).as_posix()
            # Worktree monitoring is structural: path, type, size, and mtime
            # detect writes without opening ignored or sensitive content.
            work.append((relative,info.st_size,info.st_mtime_ns,stat.S_IFMT(info.st_mode)))
            if len(work)>MAX_SNAPSHOT_FILES:raise ProvanError("TARGET_INVENTORY_LIMIT_EXCEEDED","bounded target worktree inventory exceeded")
    return {"git":sha256_bytes(canonical_bytes(rows)),"fixed":sha256_bytes(canonical_bytes(fixed)),"worktree":sha256_bytes(canonical_bytes(work))}


def _snapshot_local_target(repo: Path,working_tree: bool) -> tuple[tempfile.TemporaryDirectory,Path,str,list[dict[str,str]]]:
    before=_target_fingerprint(repo);git_dir=repo/".git"
    config=git_dir/"config";config_text=config.read_text(encoding="utf-8",errors="strict")[:1024*1024] if config.is_file() else ""
    parser=configparser.RawConfigParser(interpolation=None);origin=None
    try:
        parser.read_string(config_text)
        origin=parser.get('remote "origin"',"url",fallback=None)
    except configparser.Error as exc:raise ProvanError("LOCAL_REPOSITORY_INVALID","Git configuration is malformed") from exc
    identity=origin.removesuffix(".git") if origin and SAFE_REMOTE.fullmatch(origin) else "local:"+hashlib.sha256(((git_dir/"HEAD").read_text(errors="replace")+"\n"+repo.name).encode()).hexdigest()
    context=tempfile.TemporaryDirectory(prefix="provan-local-snapshot-");scratch=Path(context.name)/"snapshot";scratch.mkdir()
    for path in git_dir.rglob("*"):
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or (os.name=="nt" and bool(getattr(info,"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT)):
            context.cleanup();raise ProvanError("UNSAFE_GIT_OBJECT_LINK_FORBIDDEN","linked Git metadata is not copied to scratch")
    if working_tree:_copy_mutable_git_metadata(git_dir,scratch/".git")
    else:shutil.copytree(git_dir,scratch/".git",symlinks=False)
    for unsafe in (scratch/".git/config",scratch/".git/config.worktree"):
        if unsafe.exists():unsafe.unlink()
    hooks=scratch/".git/hooks"
    if hooks.exists():shutil.rmtree(hooks)
    (scratch/".git/config").write_text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = " + str(scratch).replace("\\","/") + "\n",encoding="utf-8")
    excluded=[];copied=0;files=0
    if working_tree:
        candidates=[]
        for directory,dirnames,filenames in os.walk(repo,followlinks=False):
            current=Path(directory)
            if current==repo:dirnames[:]=[name for name in dirnames if name!=".git" and not GENERATED.search(name)]
            for name in filenames:
                source=current/name;relative=source.relative_to(repo).as_posix();candidates.append((source,relative,source.lstat()))
        # Evaluate ignore policy inside isolated scratch before copying any
        # candidate content. Ignore-policy files alone are seeded first;
        # arbitrary ignored files are classified without being opened.
        for source,relative,info in candidates:
            if Path(relative).name==".gitignore" and stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_size<=1024*1024:
                target=scratch/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        encoded=b"\0".join(relative.encode("utf-8") for _,relative,_ in candidates)+b"\0"
        ignored_raw=_git(scratch,["check-ignore","--stdin","-z"],input_bytes=encoded,allowed_returncodes=(0,1)) if candidates else b""
        ignored={item.decode("utf-8","strict") for item in ignored_raw.split(b"\0") if item}
        for source,relative,info in candidates:
            if SENSITIVE.search(relative):excluded.append({"category":"SENSITIVE_PATH","relative_classification":source.suffix.lower() or "credential-class"});continue
            if relative in ignored:excluded.append({"category":"IGNORED_PATH","relative_classification":source.suffix.lower() or "ignored"});continue
            if GENERATED.search(relative):excluded.append({"category":"GENERATED_OR_OUT_OF_SCOPE","relative_classification":"generated"});continue
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or (os.name=="nt" and bool(getattr(info,"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT)):
                excluded.append({"category":"UNSAFE_OR_UNSUPPORTED_PATH","relative_classification":"non-regular"});continue
            files+=1
            if files>MAX_SNAPSHOT_FILES or copied+info.st_size>MAX_SNAPSHOT_BYTES:
                excluded.append({"category":"SNAPSHOT_LIMIT_NONCOVERAGE","relative_classification":source.suffix.lower() or "file"});continue
            target=scratch/source.relative_to(repo);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target);copied+=info.st_size
    if _target_fingerprint(repo)!=before:context.cleanup();raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED","target changed during scratch snapshot")
    return context,scratch,identity,excluded


def _repository_identity(repo: Path) -> str:
    try:
        remote = _git(repo, ["remote", "get-url", "origin"]).decode().strip()
    except ProvanError:
        remote = "local-unpublished"
    if SAFE_REMOTE.fullmatch(remote): return remote.removesuffix(".git")
    head = _git(repo, ["rev-parse", "HEAD"]).decode().strip()
    return "local:" + hashlib.sha256((head + "\n" + str(repo.name)).encode()).hexdigest()


def _name_status(raw: bytes) -> list[dict[str, str]]:
    text = raw.decode("utf-8", "strict")
    rows=[]
    for line in text.splitlines():
        if not line: continue
        fields=line.split("\t"); status=fields[0][0]; path=Path(fields[-1]).as_posix()
        if path.startswith("/") or ".." in Path(path).parts: raise ProvanError("UNSAFE_TREE_PATH_FORBIDDEN", "diff path traverses")
        rows.append({"path": path, "status": status})
    if len(rows)>MAX_CHANGED_FILES: raise ProvanError("ANALYSIS_LIMIT_EXCEEDED", "changed file count exceeds limit")
    return rows


def _classify(path: str) -> list[str]:
    suffix=Path(path).suffix.lower(); name=Path(path).name.lower(); result=[]
    if suffix in {".json", ".yaml", ".yml", ".toml"}: result.append("configuration_or_schema")
    if name in {"pyproject.toml", "package.json", "requirements.txt", "poetry.lock", "uv.lock"}: result.append("manifest_or_lockfile")
    if ".github/workflows/" in path or path.startswith(".github/workflows/"): result.append("ci")
    if "test" in Path(path).parts or name.startswith("test_"): result.append("test_or_fixture")
    if suffix==".py": result.append("python_source")
    if "schema" in name: result.append("schema")
    return result or ["unqualified_surface"]


def _runtime_schema_digest() -> str:
    root=files("provan.schemas");rows=[]
    for item in sorted(root.iterdir(),key=lambda value:value.name):
        if item.name.endswith(".json"):rows.append((item.name,sha256_bytes(item.read_bytes())))
    return sha256_bytes(canonical_bytes(rows))


def _blob(repo: Path, path: str, *, mode: str, head: str | None, remaining: int) -> tuple[bytes | None,str | None]:
    if remaining<=0:return None,"ANALYSIS_AGGREGATE_LIMIT"
    if mode=="immutable" and not head:return None,None
    if mode=="immutable":
        size=int(_git(repo,["cat-file","-s",f"{head}:{path}"]).decode())
        if size>remaining:return None,"ANALYSIS_FILE_OR_AGGREGATE_LIMIT"
        return _git(repo,["show",f"{head}:{path}"]),None
    candidate=Path(os.path.abspath(repo/path))
    try:candidate.relative_to(repo.resolve())
    except ValueError:return None,"UNSAFE_WORKTREE_PATH"
    if not candidate.exists():return None,None
    try:
        text,_=read_bounded_file(candidate,limit=remaining)
        return text.encode(),None
    except ProvanError as exc:
        return None,exc.code


def _static_details(path: str, raw: bytes) -> tuple[dict[str,Any],list[str]]:
    details={"content_digest":sha256_bytes(raw),"symbols":[],"exports":[],"imports":[],"routes":[],"dependencies":[],"schema_contract":None};limitations=[];suffix=Path(path).suffix.lower();name=Path(path).name.lower()
    try:text=raw.decode("utf-8","strict")
    except UnicodeDecodeError:return details,["NON_UTF8_STATIC_SURFACE"]
    if suffix==".py":
        try:tree=ast.parse(text)
        except SyntaxError:return details,["PYTHON_STATIC_PARSE_UNRESOLVED"]
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):details["symbols"].append(node.name)
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                if isinstance(node,ast.Import):details["imports"].extend(alias.name for alias in node.names)
                elif node.module:details["imports"].append(node.module)
            decorators=getattr(node,"decorator_list",[])
            for decorator in decorators:
                if isinstance(decorator,ast.Call) and isinstance(decorator.func,ast.Attribute) and decorator.func.attr.lower() in {"get","post","put","patch","delete","options","head"} and decorator.args and isinstance(decorator.args[0],ast.Constant) and isinstance(decorator.args[0].value,str):details["routes"].append({"method":decorator.func.attr.upper(),"path":decorator.args[0].value})
        for node in tree.body:
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                if any(isinstance(target,ast.Name) and target.id=="__all__" for target in targets):
                    try:details["exports"].extend(str(value) for value in ast.literal_eval(node.value))
                    except (ValueError,TypeError):limitations.append("DYNAMIC_PUBLIC_EXPORT_UNRESOLVED")
    elif name=="pyproject.toml":
        try:
            value=tomllib.loads(text);details["dependencies"].extend(str(item).split(" ",1)[0] for item in value.get("project",{}).get("dependencies",[]));details["symbols"].extend(value.get("project",{}).get("scripts",{}).keys())
        except (tomllib.TOMLDecodeError,AttributeError):limitations.append("MANIFEST_STATIC_PARSE_UNRESOLVED")
    elif name=="package.json":
        try:
            value=json.loads(text);details["dependencies"].extend(sorted(set(value.get("dependencies",{}))|set(value.get("devDependencies",{}))));details["symbols"].extend(value.get("scripts",{}).keys())
        except (json.JSONDecodeError,AttributeError):limitations.append("MANIFEST_STATIC_PARSE_UNRESOLVED")
    elif name in {"requirements.txt"}:
        details["dependencies"].extend(line.split(";",1)[0].split("=",1)[0].split("<",1)[0].split(">",1)[0].strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    if suffix==".json":
        try:
            parsed=json.loads(text)
            if isinstance(parsed,dict) and ("$schema" in parsed or "$id" in parsed):details["schema_contract"]={key:parsed.get(key) for key in ("$id","type","required","properties","enum","oneOf","anyOf") if key in parsed}
        except json.JSONDecodeError:pass
    for key in ("symbols","exports","imports","dependencies"):
        values=sorted(set(filter(None,details[key])))
        if len(values)>MAX_ENTITY_DETAILS:limitations.append("STATIC_ENTITY_LIMIT_NONCOVERAGE")
        details[key]=values[:MAX_ENTITY_DETAILS]
    routes=sorted({(row["method"],row["path"]):row for row in details["routes"]}.values(),key=lambda row:(row["method"],row["path"]))
    if len(routes)>MAX_ENTITY_DETAILS:limitations.append("STATIC_ENTITY_LIMIT_NONCOVERAGE")
    details["routes"]=routes[:MAX_ENTITY_DETAILS]
    return details,limitations


def _entities_and_relationships(rows: list[dict[str,Any]]) -> tuple[list[dict[str,Any]],list[dict[str,Any]],list[str]]:
    entities=[];relationships=[];seen={};limitations=[];entity_truncated=False
    def entity(kind,scope,state="referenced",evidence_ref=None):
        nonlocal entity_truncated
        key=(kind,scope)
        if key in seen:
            value=seen[key]
            if evidence_ref and evidence_ref not in value["evidence_refs"]:value["evidence_refs"].append(evidence_ref)
            return value
        if len(seen)>=MAX_ENTITY_DETAILS:entity_truncated=True;return None
        value={"schema_id":"provan.affected_entity.v1","entity_id":sha256_bytes(canonical_bytes({"kind":kind,"scope":scope})),"kind":kind,"scope":scope,"state":state,"authority":"source_established","evidence_refs":[evidence_ref or scope]};seen[key]=value;entities.append(value);return value
    for row in rows:
        source=entity("file",row["path"],row["status"]);details=row.get("static_details",{})
        if source is None:continue
        targets=[("symbol",name,"declares") for name in details.get("symbols",[])]+[("module",name,"imports") for name in details.get("imports",[])]+[("dependency",name,"declares_dependency") for name in details.get("dependencies",[])]+[("route",item["method"]+" "+item["path"],"declares_route") for item in details.get("routes",[])]
        for kind,scope,relation in targets[:MAX_ENTITY_DETAILS]:
            target=entity(kind,scope,evidence_ref=row["path"])
            if target is None:continue
            relationship_id=sha256_bytes(canonical_bytes({"source":source["entity_id"],"target":target["entity_id"],"relation":relation}));relationships.append({"schema_id":"provan.affected_relationship.v1","relationship_id":relationship_id,"source_entity_id":source["entity_id"],"target_entity_id":target["entity_id"],"relation":relation,"authority":"source_established","evidence_refs":[row["path"]]})
    if entity_truncated:limitations.append("GLOBAL_ENTITY_LIMIT_NONCOVERAGE")
    if len(relationships)>MAX_ENTITY_DETAILS:limitations.append("GLOBAL_RELATIONSHIP_LIMIT_NONCOVERAGE")
    return entities,relationships[:MAX_ENTITY_DETAILS],limitations


def _analyse_local(repo: Path, *, base: str | None, head: str | None, working_tree: bool, identity_override: str | None = None, initial_excluded: list[dict[str,str]] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    git_directory=repo/".git"
    if not git_directory.is_dir() or git_directory.is_symlink(): raise ProvanError("LOCAL_REPOSITORY_INVALID", "local repository must have a non-linked .git directory")
    before=_repo_fingerprint(repo); identity=identity_override or _repository_identity(repo)
    limitations=[]; excluded=list(initial_excluded or []); index_rows=[]
    if working_tree:
        resolved_head=_git(repo,["rev-parse","HEAD"]).decode().strip()
        rows=_name_status(_git(repo,["diff","--no-ext-diff","--no-textconv","--name-status","HEAD","--"]));
        index_rows=_name_status(_git(repo,["diff","--cached","--no-ext-diff","--no-textconv","--name-status","HEAD","--"]));
        untracked=_git(repo,["ls-files","--others","--exclude-standard","-z"]).decode("utf-8","strict").split("\0")
        for path in filter(None,untracked): rows.append({"path":Path(path).as_posix(),"status":"?"})
        ignored=_git(repo,["ls-files","--others","--ignored","--exclude-standard","-z"]).decode("utf-8","strict").split("\0")
        for path in filter(None,ignored):excluded.append({"category":"IGNORED_PATH","relative_classification":Path(path).suffix.lower() or "ignored"})
        filtered=[]
        for row in rows:
            if SENSITIVE.search(row["path"]): excluded.append({"category":"SENSITIVE_PATH","relative_classification":Path(row["path"]).suffix.lower() or "credential-class"}); continue
            if GENERATED.search(row["path"]): excluded.append({"category":"GENERATED_OR_OUT_OF_SCOPE","relative_classification":"generated"}); continue
            filtered.append(row)
        clean_index=[]
        for row in index_rows:
            if SENSITIVE.search(row["path"]):excluded.append({"category":"SENSITIVE_INDEX_PATH","relative_classification":Path(row["path"]).suffix.lower() or "credential-class"})
            else:clean_index.append(row)
        index_rows=clean_index;rows=filtered;base=resolved_head;head=None
        mode="mutable"
    else:
        if not base or not head or not FULL_COMMIT.fullmatch(base) or not FULL_COMMIT.fullmatch(head): raise ProvanError("PINNED_COMMIT_REQUIRED","immutable mode requires full base and head IDs")
        base=_git(repo,["rev-parse","--verify",base+"^{commit}"]).decode().strip(); head=_git(repo,["rev-parse","--verify",head+"^{commit}"]).decode().strip()
        rows=_name_status(_git(repo,["diff","--no-ext-diff","--no-textconv","--name-status",base,head,"--"])); work_digest=None; mode="immutable"
    classified=[];used=0
    empty_details={"content_digest":None,"symbols":[],"exports":[],"imports":[],"routes":[],"dependencies":[],"schema_contract":None}
    for row in rows:
        current={**row,"surface_classes":_classify(row["path"])}
        raw,reason=(None,None) if row["status"]=="D" else _blob(repo,row["path"],mode=mode,head=head,remaining=MAX_ANALYSIS_BYTES-used)
        if raw is not None:
            used+=len(raw);details,static_limits=_static_details(row["path"],raw);current["static_details"]=details;limitations.extend(static_limits)
        elif reason:limitations.append(reason);current["static_details"]=dict(empty_details)
        else:current["static_details"]=dict(empty_details)
        old_raw=None
        if row["status"]!="A" and base:
            try:
                old_size=int(_git(repo,["cat-file","-s",f"{base}:{row['path']}"]).decode())
                if old_size<=MAX_ANALYSIS_BYTES:old_raw=_git(repo,["show",f"{base}:{row['path']}"])
                else:limitations.append("BASELINE_ANALYSIS_LIMIT_NONCOVERAGE")
            except ProvanError:old_raw=None
        old_details=_static_details(row["path"],old_raw)[0] if old_raw is not None else dict(empty_details)
        current["baseline_static_details"]=old_details
        current["verified_triggers"]=[]
        new_details=current["static_details"]
        public_delta=(old_details.get("exports")!=new_details.get("exports") and bool(old_details.get("exports") or new_details.get("exports"))) or old_details.get("routes")!=new_details.get("routes") or old_details.get("schema_contract")!=new_details.get("schema_contract")
        manifest_delta=Path(row["path"]).name.lower() in {"pyproject.toml","package.json"} and (old_details.get("dependencies")!=new_details.get("dependencies") or old_details.get("symbols")!=new_details.get("symbols"))
        if public_delta or manifest_delta:current["verified_triggers"].append("PUBLIC_CONTRACT_CHANGED")
        classified.append(current)
    added_digests={row["static_details"].get("content_digest") for row in classified if row["status"]=="A" and row["static_details"].get("content_digest")}
    for row in classified:
        # A deleted test/fixture is a concrete weakening only when its exact
        # content was not reintroduced elsewhere in the same candidate. CI
        # filename deletion alone is not enough to infer scope reduction.
        old_digest=row["baseline_static_details"].get("content_digest")
        if row["status"]=="D" and "test_or_fixture" in row["surface_classes"] and old_digest and old_digest not in added_digests:
            row["verified_triggers"].append("VERIFICATION_SURFACE_WEAKENED")
    if mode=="mutable":work_digest=sha256_bytes(canonical_bytes({"rows":[{"path":row["path"],"status":row["status"],"content_digest":row["static_details"]["content_digest"]} for row in classified],"index":index_rows,"index_digest":before["index"],"excluded":excluded}))
    after=_repo_fingerprint(repo)
    if any(before[key]!=after[key] for key in ("head","refs","objects")): raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED","scratch repository refs or object state changed")
    candidate_core={"repository_identity":identity,"mode":mode,"base":base,"head":head,"working_tree_digest":work_digest}
    candidate={**candidate_core,"candidate_digest":sha256_bytes(canonical_bytes(candidate_core))}
    if any("unqualified_surface" in row["surface_classes"] for row in classified):limitations.append("UNSUPPORTED_OR_DYNAMIC_SURFACE_NONCOVERAGE")
    if excluded:limitations.append("MUTABLE_SENSITIVE_OR_GENERATED_SURFACES_EXCLUDED_WITHOUT_CONTENT_READ")
    analysis={"changed_files":classified,"index_changes":index_rows,"excluded_sensitive_surfaces":excluded,"limitations":sorted(set(limitations)),"analysis_bytes":used,"target_state_before":before,"target_state_after":after}
    return candidate,analysis


def _source_claim(row: dict[str,Any]) -> dict[str,Any]:
    core={"changed_file":row["path"],"status":row["status"],"verified_triggers":sorted(set(row.get("verified_triggers",[])))}
    return {**core,"fact_digest":sha256_bytes(canonical_bytes(core))}


def _promotion(analysis: dict[str, Any], case_id: str, proposal_texts: list[str] | None = None) -> dict[str, Any]:
    applied=[]; unresolved=[]
    for row in analysis["changed_files"]:
        path=row["path"]
        for reason in row.get("verified_triggers",[]):
            claim=_source_claim(row)
            applied.append({"reason":reason,"authority":"configuration_verified" if reason=="VERIFICATION_SURFACE_WEAKENED" else "source_verified","evidence_ref":path,"source_fact_digest":claim["fact_digest"]})
    applied=list({(r["reason"],r["evidence_ref"]):r for r in applied}.values())
    proposal_codes={"RELEVANT_PRIOR_INCIDENT","OWNER_REQUESTED","HIGH_BLAST_RADIUS","DIFFICULT_REVERSIBILITY","FALSE_SUCCESS_RISK"}
    joined="\n".join(proposal_texts or [])
    unresolved=[{"reason":code,"authority":"unresolved_proposal","source":"case_supplied_text"} for code in sorted(proposal_codes) if code in joined]
    return {"schema_id":"provan.promotion_decision.v1","case_id":case_id,"policy_id":POLICY_ID,"policy_version":POLICY_VERSION,"decision":"acceptance_recommended" if applied else "explain_only","applied_triggers":applied,"unresolved_proposals":unresolved}


class ContextProvider(Protocol):
    provider_id: str
    def collect(self, case_id: str, context_files: list[Path], aliases: list[str], journeys: list[str], journey_files: list[Path]) -> tuple[dict[str,Any],dict[str,Any]]: ...


class CaseLocalContextProvider:
    provider_id = "CaseLocalContextProvider"
    def collect(self, case_id: str, context_files: list[Path], aliases: list[str], journeys: list[str], journey_files: list[Path]) -> tuple[dict[str,Any],dict[str,Any]]:
        return _collect_case_context(case_id, context_files, aliases, journeys, journey_files)


def _collect_case_context(case_id: str, context_files: list[Path], aliases: list[str], journeys: list[str], journey_files: list[Path]) -> tuple[dict[str,Any],dict[str,Any]]:
    if len(context_files)>16 or len(journey_files)>8: raise ProvanError("INPUT_FILE_TOO_LARGE","too many explicit files")
    records=[]; total=0
    for path in context_files:
        text,_=read_bounded_file(path,limit=1024*1024); total+=len(text.encode());
        if total>4*1024*1024: raise ProvanError("INPUT_FILE_TOO_LARGE","context aggregate exceeds 4 MiB")
        records.append({"schema_id":"provan.context_record.v1","case_id":case_id,"source_type":"case_local_file","source_reference":path.name,"scope":"case","lifecycle":"ephemeral","authority":"source_attributed","content_digest":sha256_bytes(text.encode()),"citation":path.name})
    parsed_journeys=[{"text":item,"authority":"source_attributed_proposal","source":"literal"} for item in journeys]
    journey_total=0
    for path in journey_files:
        text,value=read_bounded_file(path,limit=256*1024,structured=True); journey_total+=len(text.encode())
        if journey_total>1024*1024: raise ProvanError("INPUT_FILE_TOO_LARGE","journey aggregate exceeds 1 MiB")
        items=value if isinstance(value,list) else value.get("journeys",[]) if isinstance(value,dict) else []
        if not all(isinstance(item,(str,dict)) for item in items): raise ProvanError("USER_JOURNEY_STRUCTURE_INVALID","journey file must contain a list")
        for item in items: parsed_journeys.append({"text":item if isinstance(item,str) else str(item.get("text","")),"authority":"source_attributed_proposal","source":path.name})
    bundle={"schema_id":"provan.case_context_bundle.v1","case_id":case_id,"records":records,"aliases":[{"proposal":a,"authority":"case_local_identity_proposal"} for a in aliases],"journeys":parsed_journeys,"omissions":[],"limitations":["NO_OWNER_CONFIRMATION_PATH","NO_ORGANISATION_POLICY_PATH"]}
    request={"schema_id":"provan.context_request.v1","case_id":case_id,"file_digests":[r["content_digest"] for r in records],"aliases":aliases,"journey_digests":[sha256_bytes(canonical_bytes(j)) for j in parsed_journeys]}
    validate_context_bundle_serialized(canonical_bytes(bundle)); return request,bundle


def _cache_fragment(candidate: dict[str,Any], analysis: dict[str,Any]) -> dict[str,Any]:
    monitored_state={"before":analysis.get("target_state_before"),"after":analysis.get("target_state_after")}
    key_inputs={"repository_identity":candidate["repository_identity"],"base":candidate["base"],"head":candidate["head"],"working_tree_digest":candidate["working_tree_digest"],"target_state_digest":sha256_bytes(canonical_bytes(monitored_state)),"schema_registry":_runtime_schema_digest(),"mapper":"1","parser":"1","analysis_limits":"1"}
    key=sha256_bytes(canonical_bytes(key_inputs)); relative=Path("cache/repository-analysis")/key.removeprefix("sha256:")/"fragment.json"
    fragment={"schema_id":"provan.repository_analysis_cache_fragment.v1","case_id":None,"cache_key":key,"key_inputs":key_inputs,"analysis":analysis,"analysis_digest":sha256_bytes(canonical_bytes(analysis))}
    raw=canonical_bytes(fragment)
    try: secure_write(relative,raw)
    except FileExistsError:
        existing=secure_read(relative); validate_cache_fragment_serialized(existing,key_inputs,analysis); fragment=json.loads(existing)
    validate_cache_fragment_serialized(canonical_bytes(fragment),key_inputs,analysis); return fragment


def _previous_from_manifest(manifest_path: Path) -> tuple[dict[str,Any],dict[str,Any]]:
    text,manifest=read_bounded_file(manifest_path,limit=1024*1024,structured=True)
    if not isinstance(manifest,dict) or manifest.get("schema_id")!="provan.change_brief_export_manifest.v1":
        raise ProvanError("PREVIOUS_BRIEF_MANIFEST_INVALID","only a manifest-backed Provan export is accepted")
    schema=json.loads(files("provan.schemas").joinpath("change-brief-export-manifest.v1.json").read_text(encoding="utf-8"))
    try:validate_schema_instance(manifest,schema)
    except StructuralValidationError as exc:raise ProvanError("PREVIOUS_BRIEF_MANIFEST_INVALID",f"manifest structure failed {exc.keyword} at {list(exc.path)}") from exc
    validate_previous_export_manifest_serialized(canonical_bytes(manifest))
    refs=manifest.get("artifacts",[])
    if not isinstance(refs,list) or len(refs)>256: raise ProvanError("PREVIOUS_BRIEF_EXPORT_TOO_LARGE","export artifact count exceeds limit")
    root=manifest_path.resolve().parent; total=0; brief=None; seen=set();exported=[];artifact_closure={}
    role_schemas={"change_brief":"provan.change_brief.v1","context_bundle":"provan.case_context_bundle.v1","context_request":"provan.context_request.v1","context_provider_result":"provan.context_provider_result.v1","promotion_decision":"provan.promotion_decision.v1","acceptance_seed":"provan.acceptance_seed.v1","change_topology":"provan.change_topology.v1","model_usage_receipt":"provan.model_usage_receipt.v1","model_input_envelope":"provan.model_input_envelope.v1","public_projection":"provan.change_brief_public_projection.v1"}
    for ref in refs:
        relative=Path(str(ref.get("path","")))
        if relative.is_absolute() or any(part in {"",".",".."} for part in relative.parts) or relative.as_posix() in seen:
            raise ProvanError("PREVIOUS_BRIEF_EXPORT_PATH_UNSAFE","export path is absolute, traversing, or duplicated")
        seen.add(relative.as_posix()); candidate=root/relative
        try: candidate.resolve().relative_to(root)
        except (ValueError,OSError) as exc: raise ProvanError("PREVIOUS_BRIEF_EXPORT_PATH_UNSAFE","export artifact escapes its root") from exc
        raw_text,_=read_bounded_file(candidate,limit=8*1024*1024); raw=raw_text.encode(); total+=len(raw)
        if total>32*1024*1024: raise ProvanError("PREVIOUS_BRIEF_EXPORT_TOO_LARGE","export aggregate exceeds 32 MiB")
        if len(raw)!=ref.get("size") or sha256_bytes(raw)!=ref.get("sha256"): raise ProvanError("PREVIOUS_BRIEF_DIGEST_MISMATCH","export artifact size or digest mismatch")
        if candidate.suffix.lower()!=".json":raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_SCHEMA_UNSUPPORTED","Session 10 accepts only canonical JSON export artifacts")
        try:artifact_value=json.loads(raw)
        except json.JSONDecodeError as exc:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_SCHEMA_INVALID","export JSON artifact is invalid") from exc
        artifact_schema=artifact_value.get("schema_id") if isinstance(artifact_value,dict) else None;expected_schema=role_schemas.get(ref.get("role"))
        if not expected_schema or ref.get("schema_id")!=expected_schema or artifact_schema!=expected_schema:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_ROLE_MISMATCH","export role and schema are not canonically bound")
        if ref.get("sensitivity") not in ({"PUBLIC_SAFE"} if ref.get("role")=="public_projection" else {"LOCAL_NON_PUBLIC"}):raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_SENSITIVITY_INVALID","export sensitivity does not match its canonical role")
        packaged=None
        for schema_item in files("provan.schemas").iterdir():
            if schema_item.name.endswith(".json"):
                schema_value=json.loads(schema_item.read_text(encoding="utf-8"))
                if schema_value.get("$id")==artifact_schema:packaged=schema_value;break
        if packaged is None:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_SCHEMA_UNSUPPORTED","export artifact schema is not packaged")
        try:validate_schema_instance(artifact_value,packaged)
        except StructuralValidationError as exc:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_SCHEMA_INVALID",f"artifact structure failed {exc.keyword}") from exc
        exported.append((artifact_schema,artifact_value,raw))
        artifact_closure[relative.as_posix()]=raw_text
        if ref.get("role")=="change_brief": brief=json.loads(raw)
    if not brief: raise ProvanError("PREVIOUS_BRIEF_MANIFEST_INVALID","export has no canonical Change Brief")
    if manifest["repository_identity"]!=brief.get("candidate",{}).get("repository_identity") or manifest["previous_head"]!=brief.get("candidate",{}).get("head"):
        raise ProvanError("PREVIOUS_BRIEF_MANIFEST_PROVENANCE_MISMATCH","manifest authority does not bind the exported Brief")
    validate_change_brief_serialized(canonical_bytes(brief));_validate_previous_artifacts(brief,exported); return brief,{"kind":"manifest_export","manifest":manifest,"manifest_digest":sha256_bytes(canonical_bytes(manifest)),"artifact_closure":artifact_closure,"brief_id":brief["brief_id"],"candidate_digest":brief["candidate"]["candidate_digest"]}


def _validate_previous_artifacts(brief: dict[str,Any], artifacts: list[tuple[str,dict[str,Any],bytes]]) -> None:
    case_id=brief["case_id"];candidate=brief["candidate"];entities=brief["entities"];relationships=brief["relationships"];entity_ids={row["entity_id"] for row in entities};bundle=brief["context_bundle"];promotion=brief["promotion_decision"]
    for schema_id,value,raw in artifacts:
        if schema_id=="provan.change_brief.v1" and value!=brief:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","export contains divergent Brief artifacts")
        if schema_id=="provan.case_context_bundle.v1":
            validate_context_bundle_serialized(raw)
            if value!=bundle:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","context bundle diverges from Brief")
        elif schema_id=="provan.context_request.v1":
            validate_context_request_serialized(raw,bundle)
            if value!=brief["context_request"]:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","context request diverges from Brief")
        elif schema_id=="provan.context_provider_result.v1":validate_provider_result_serialized(raw,bundle)
        elif schema_id=="provan.promotion_decision.v1":
            validate_promotion_serialized(raw,case_id,brief.get("claims",{}).get("source_established",[]),brief.get("analysis_evidence",[]))
            if value!=promotion:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","promotion diverges from Brief")
        elif schema_id=="provan.acceptance_seed.v1":
            validate_acceptance_seed_serialized(raw,candidate,case_id,promotion,entity_ids,bundle)
            if value!=brief["acceptance_seed"]:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","Acceptance Seed diverges from Brief")
        elif schema_id=="provan.change_topology.v1":validate_topology_serialized(raw,entities,relationships)
        elif schema_id=="provan.model_usage_receipt.v1":validate_model_usage_serialized(raw,brief.get("model_input_envelope_digest"))
        elif schema_id=="provan.model_input_envelope.v1":
            validate_model_envelope_serialized(raw,{"case_id":case_id,"candidate_digest":candidate["candidate_digest"],"provider":brief.get("model_usage",{}).get("provider"),"model":brief.get("model_usage",{}).get("model"),"prompt_id":brief.get("model_usage",{}).get("prompt_id"),"prompt_version":brief.get("model_usage",{}).get("prompt_version")})
            if sha256_bytes(raw)!=brief.get("model_input_envelope_digest"):raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","model envelope diverges from Brief")
        elif schema_id=="provan.change_brief_public_projection.v1":
            validate_public_projection_serialized(raw)
            if value.get("brief_id")!=brief["brief_id"] or value.get("candidate_digest")!=candidate["candidate_digest"]:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_MISMATCH","public projection diverges from Brief")


def _previous_from_id(brief_id: str) -> tuple[dict[str,Any],dict[str,Any]]:
    if not re.fullmatch(r"[0-9a-f-]{36}",brief_id): raise ProvanError("PREVIOUS_BRIEF_ID_INVALID","previous Brief ID is not canonical")
    root=state_root()/"outputs"/"change-brief"/brief_id; manifest_path=root/"manifest.json"; brief_path=root/"change-brief.json"
    if not manifest_path.is_file() or not brief_path.is_file(): raise ProvanError("PREVIOUS_BRIEF_NOT_FOUND","canonical previous Brief is unavailable")
    manifest_raw=secure_read(Path("outputs/change-brief")/brief_id/"manifest.json");manifest=json.loads(manifest_raw);_schema_validate("change-brief-manifest.v1.json",manifest)
    artifact_bytes={}
    for name in manifest.get("artifacts",{}):
        pure=Path(name)
        if pure.is_absolute() or len(pure.parts)!=1 or pure.name!=name:raise ProvanError("PREVIOUS_BRIEF_EXPORT_PATH_UNSAFE","canonical manifest artifact path is unsafe")
        artifact_bytes[name]=secure_read(Path("outputs/change-brief")/brief_id/name)
    validate_manifest_serialized(manifest_raw,artifact_bytes)
    raw=artifact_bytes.get("change-brief.json")
    if raw is None:raise ProvanError("PREVIOUS_BRIEF_DIGEST_MISMATCH","canonical previous Brief is absent")
    validate_change_brief_serialized(raw);value=json.loads(raw);exported=[];artifact_closure={}
    for name,content in artifact_bytes.items():
        try:item=json.loads(content)
        except json.JSONDecodeError as exc:raise ProvanError("PREVIOUS_BRIEF_ARTIFACT_SCHEMA_INVALID","canonical artifact JSON is invalid") from exc
        exported.append((item.get("schema_id"),item,content));artifact_closure[name]=content.decode("utf-8")
    _validate_previous_artifacts(value,exported);return value,{"kind":"canonical_id","brief_id":brief_id,"manifest":manifest,"manifest_digest":sha256_bytes(canonical_bytes(manifest)),"artifact_closure":artifact_closure,"candidate_digest":value["candidate"]["candidate_digest"]}


def _compare_previous(repo: Path, candidate: dict[str,Any], current_entities: list[dict[str,Any]], previous: dict[str,Any]) -> dict[str,Any]:
    prior=previous["candidate"]
    if prior["repository_identity"]!=candidate["repository_identity"]: raise ProvanError("PREVIOUS_BRIEF_REPOSITORY_MISMATCH","previous Brief belongs to a different repository")
    previous_ref=prior.get("head") or prior.get("base"); current_ref=candidate.get("head") or candidate.get("base")
    try: _git(repo,["merge-base","--is-ancestor",previous_ref,current_ref])
    except ProvanError as exc: raise ProvanError("PREVIOUS_BRIEF_LINEAGE_MISMATCH","previous Brief is not an ancestor-compatible comparison") from exc
    old={row["entity_id"]:row for row in previous.get("entities",[])}; new={row["entity_id"]:row for row in current_entities}
    return {"status":"COMPARABLE","previous_brief_id":previous["brief_id"],"added":sorted(set(new)-set(old)),"removed":sorted(set(old)-set(new)),"changed":sorted(k for k in set(new)&set(old) if new[k]!=old[k]),"authority":"comparison_only_not_current_evidence"}


def _bind_previous_lineage(repo: Path, candidate: dict[str,Any], previous: dict[str,Any], binding: dict[str,Any]) -> dict[str,Any]:
    prior=previous["candidate"]
    if prior["repository_identity"]!=candidate["repository_identity"]:raise ProvanError("PREVIOUS_BRIEF_REPOSITORY_MISMATCH","previous Brief belongs to a different repository")
    previous_ref=prior.get("head") or prior.get("base");current_ref=candidate.get("head") or candidate.get("base")
    try:_git(repo,["merge-base","--is-ancestor",previous_ref,current_ref])
    except ProvanError as exc:raise ProvanError("PREVIOUS_BRIEF_LINEAGE_MISMATCH","previous Brief is not an ancestor-compatible comparison") from exc
    return {**binding,"repository_identity":prior["repository_identity"],"previous_head":previous_ref,"current_head":current_ref,"lineage_status":"ANCESTOR"}


def explain(*, repo: str, base: str | None, head: str | None, working_tree: bool, brief_text: str | None,
            agent_claim: str | None, context_files: list[Path], aliases: list[str], journeys: list[str], journey_files: list[Path],
            previous_brief: str | None, previous_manifest: Path | None, provider_id: str | None, no_model: bool, pr: str | None = None) -> dict[str,Any]:
    scratch_context=None;target_repo=None;target_before=None
    if "://" in repo:
        if working_tree or not SAFE_REMOTE.fullmatch(repo) or not base or not head or not FULL_COMMIT.fullmatch(base) or not FULL_COMMIT.fullmatch(head):
            raise ProvanError("REPOSITORY_ORIGIN_NOT_ALLOWED","remote explain requires credential-free canonical GitHub HTTPS and pinned commits")
        scratch_context=tempfile.TemporaryDirectory(prefix="provan-explain-"); local_repo=Path(scratch_context.name)/"snapshot"; local_repo.mkdir()
        _git(local_repo,["init"]); _git(local_repo,["remote","add","origin",repo]); _bounded_remote_fetch(local_repo,["fetch","--no-tags","--no-write-fetch-head","--depth=1","origin",base,head],timeout=120)
        _git(local_repo,["update-ref","refs/heads/provan-inspection",head]); _git(local_repo,["symbolic-ref","HEAD","refs/heads/provan-inspection"]); _git(local_repo,["read-tree",head])
    else:
        target_repo=Path(repo).resolve();target_before=_target_fingerprint(target_repo)
        scratch_context,local_repo,identity,initial_excluded=_snapshot_local_target(target_repo,working_tree)
    try: candidate,analysis=_analyse_local(local_repo,base=base,head=head,working_tree=working_tree)
    except Exception:
        if scratch_context: scratch_context.cleanup()
        raise
    if "://" not in repo:
        candidate_core={**candidate,"repository_identity":identity};candidate_core.pop("candidate_digest",None);candidate={**candidate_core,"candidate_digest":sha256_bytes(canonical_bytes(candidate_core))}
        analysis["excluded_sensitive_surfaces"]=initial_excluded+analysis["excluded_sensitive_surfaces"]
        if initial_excluded:
            analysis["limitations"]=sorted(set(analysis["limitations"]+["MUTABLE_SENSITIVE_OR_GENERATED_SURFACES_EXCLUDED_WITHOUT_CONTENT_READ"]))
        target_after=_target_fingerprint(target_repo);analysis["target_state_before"]=target_before;analysis["target_state_after"]=target_after
        if target_before!=target_after:raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED","target changed during scratch-only analysis")
    pr_metadata=resolve_pr_metadata(repo,pr,base or "",head or "") if pr else None
    if pr_metadata and brief_text is None: brief_text=(pr_metadata["title"]+"\n\n"+pr_metadata["body"]).strip()
    if previous_brief and previous_manifest: raise ProvanError("PREVIOUS_BRIEF_INPUT_CONFLICT","select canonical ID or manifest, not both")
    prior,previous_binding=_previous_from_id(previous_brief) if previous_brief else _previous_from_manifest(previous_manifest) if previous_manifest else (None,None)
    if prior and previous_binding:previous_binding=_bind_previous_lineage(local_repo,candidate,prior,previous_binding)
    instructions="Identify bounded implications and unresolved questions. Do not assert source facts or Acceptance authority."
    provider=None if no_model else selected_provider(provider_id)
    request,bundle=CaseLocalContextProvider().collect("PENDING_CASE_BINDING",context_files,aliases,journeys,journey_files)
    context_binding={"file_digests":request["file_digests"],"aliases":request["aliases"],"journey_digests":request["journey_digests"]}
    model_binding={"mode":"NO_MODEL" if no_model else "CONFIGURED" if provider else "DETERMINISTIC_FALLBACK","provider":provider and provider.provider_id,"model":provider and provider.model,"provider_version":provider and provider.version,"prompt_id":"change-brief-synthesis","prompt_version":"1","instructions_digest":sha256_bytes(instructions.encode())}
    pr_core={"repository_identity":repo.removesuffix(".git"),"number":pr_metadata["number"],"base":pr_metadata["base"],"head":pr_metadata["head"]} if pr_metadata else None
    pr_provenance={**pr_core,"metadata_digest":sha256_bytes(canonical_bytes(pr_core))} if pr_core else None
    previous_provenance={**previous_binding,"binding_digest":sha256_bytes(canonical_bytes(previous_binding))} if previous_binding else None
    case_inputs={"candidate":candidate["candidate_digest"],"brief":sha256_bytes((brief_text or "").encode()),"agent":sha256_bytes((agent_claim or "").encode()),"context_request":sha256_bytes(canonical_bytes(context_binding)),"previous":previous_binding,"model":model_binding,"policy":{"id":POLICY_ID,"version":POLICY_VERSION},"pr":pr_metadata and pr_metadata["number"]}
    case_id=sha256_bytes(canonical_bytes(case_inputs)); brief_id=str(uuid.uuid4());request["case_id"]=case_id;bundle["case_id"]=case_id
    for record in bundle["records"]:record["case_id"]=case_id
    validate_context_bundle_serialized(canonical_bytes(bundle))
    fragment=_cache_fragment(candidate,analysis); promotion=_promotion(fragment["analysis"],case_id,[brief_text or "",agent_claim or "",*journeys]); source_claims=[_source_claim(row) for row in analysis["changed_files"]]; validate_promotion_serialized(canonical_bytes(promotion),case_id,source_claims,analysis["changed_files"])
    envelope=None; model_implications=[];root=Path("outputs/change-brief")/brief_id
    if provider:
        selected_rows=analysis["changed_files"][:64]
        if len(analysis["changed_files"])>64:analysis["limitations"].append("MODEL_CHANGED_FILE_SELECTION_LIMIT_NONCOVERAGE")
        blocks=[{"category":"candidate_summary","content":json.dumps({"changed_files":selected_rows},sort_keys=True)},{"category":"case_product_intent","content":brief_text or ""}]
        try:
            envelope=build_envelope(case_id=case_id,candidate_digest=candidate["candidate_digest"],provider=provider,instructions=instructions,blocks=blocks)
            envelope_raw=canonical_bytes(envelope);_schema_validate("model-input-envelope.v1.json",envelope);validate_model_envelope_serialized(envelope_raw,{"case_id":case_id,"candidate_digest":candidate["candidate_digest"],"provider":provider.provider_id,"model":provider.model,"provider_version":provider.version,"prompt_id":"change-brief-synthesis","prompt_version":"1","instructions":instructions});secure_write(root/"model-input-envelope.json",envelope_raw)
            try:result,usage=invoke(provider,envelope)
            except Exception:
                attempted={"schema_id":"provan.model_usage_receipt.v1","mode":"EXECUTED","provider":provider.provider_id,"model":provider.model,"prompt_id":envelope["prompt_id"],"prompt_version":envelope["prompt_version"],"envelope_digest":sha256_bytes(envelope_raw),"calls":1,"latency_ms":None,"latency_source":"unavailable","cost_status":"unavailable"};secure_write(root/"model-usage-receipt.json",canonical_bytes(attempted));raise
            secure_write(root/"model-usage-receipt.json",canonical_bytes(usage));model_implications=result.get("model_reviewed_implications",[]);analysis["limitations"].extend(result.get("unresolved",[]))
        except ProvanError as exc:
            if exc.code!="MODEL_INPUT_LIMIT_EXCEEDED":raise
            envelope=None;usage=zero_usage("DETERMINISTIC_FALLBACK");analysis["limitations"].append("MODEL_INPUT_LIMIT_EXCEEDED")
    else: usage=zero_usage("NO_MODEL" if no_model else "DETERMINISTIC_FALLBACK")
    if target_repo is not None and target_before is not None and _target_fingerprint(target_repo)!=target_before:
        if scratch_context:scratch_context.cleanup()
        raise ProvanError("INSPECTION_READ_ONLY_INVARIANT_FAILED","target changed during the bounded model-provider phase")
    entities,relationships,entity_limits=_entities_and_relationships(analysis["changed_files"]);analysis["limitations"]=sorted(set(analysis["limitations"]+entity_limits))
    seed={"schema_id":"provan.acceptance_seed.v1","seed_id":str(uuid.uuid4()),"case_id":case_id,"candidate_digest":candidate["candidate_digest"],"status":"proposed","acceptance_eligible":candidate["mode"]=="immutable","policy_id":POLICY_ID,"policy_version":POLICY_VERSION,"decision":promotion["decision"],"trigger_refs":promotion["applied_triggers"],"context_digest":sha256_bytes(canonical_bytes(bundle)),"evidence_refs":[e["entity_id"] for e in entities],"unresolved_questions":analysis["limitations"]}
    comparison=_compare_previous(local_repo,candidate,entities,prior) if prior else {"status":"NOT_SUPPLIED"}
    topology_rendered=len(entities)>=8 or len(relationships)>=6
    topology={"schema_id":"provan.change_topology.v1","case_id":case_id,"rendered":topology_rendered,"threshold_rule":"entities>=8_or_relationships>=6","nodes":entities if topology_rendered else [],"edges":relationships if topology_rendered else [],"text_fallback":"; ".join(f"{e['state']} {e['scope']} ({e['authority']})" for e in entities) or "No changed entity was established."}
    provider_result={"schema_id":"provan.context_provider_result.v1","provider_id":"CaseLocalContextProvider","case_id":case_id,"records":bundle["records"],"omissions":bundle["omissions"],"limitations":bundle["limitations"],"canonical_proof":False}
    brief={"schema_id":"provan.change_brief.v1","brief_id":brief_id,"case_id":case_id,"case_binding":case_inputs,"case_provenance":{"previous":previous_provenance,"pr":pr_provenance},"candidate":candidate,"analysis_evidence":analysis["changed_files"],"claims":{"agent_reported":[agent_claim] if agent_claim else [],"source_attributed_product_intent":[brief_text] if brief_text else [],"source_established":source_claims,"model_reviewed_implications":model_implications,"unresolved":analysis["limitations"]},"entities":entities,"relationships":relationships,"context_request":request,"context_bundle":bundle,"promotion_decision":promotion,"acceptance_seed":seed,"model_usage":usage,"model_input_envelope_digest":sha256_bytes(canonical_bytes(envelope)) if envelope else None,"previous_comparison":comparison,"limitations":analysis["limitations"],"next_action":"Review the proposed Change Brief before Session 11 confirmation."}
    for filename,value in (("change-brief.v1.json",brief),("case-context-bundle.v1.json",bundle),("context-request.v1.json",request),("context-provider-result.v1.json",provider_result),("promotion-decision.v1.json",promotion),("acceptance-seed.v1.json",seed),("change-topology.v1.json",topology),("model-usage-receipt.v1.json",usage)):_schema_validate(filename,value)
    for entity in entities:_schema_validate("affected-entity.v1.json",entity)
    for relationship in relationships:_schema_validate("affected-relationship.v1.json",relationship)
    validate_change_brief_serialized(canonical_bytes(brief));validate_provider_result_serialized(canonical_bytes(provider_result),bundle);validate_topology_serialized(canonical_bytes(topology),entities,relationships)
    public_projection={"schema_id":"provan.change_brief_public_projection.v1","sensitivity":"PUBLIC_SAFE","brief_id":brief_id,"candidate_digest":candidate["candidate_digest"],"mode":candidate["mode"],"changed_surface_counts":{kind:sum(kind in row["surface_classes"] for row in analysis["changed_files"]) for kind in sorted({kind for row in analysis["changed_files"] for kind in row["surface_classes"]})},"promotion":promotion["decision"],"limitations":analysis["limitations"],"model_audit":{"calls":usage["calls"],"provider":usage["provider"],"prompt_version":usage["prompt_version"],"envelope_digest":usage["envelope_digest"]},"summary":"Deterministically sanitised Change Brief projection; inspect the local canonical artifact for source paths and exact context."}
    _schema_validate("change-brief-public-projection.v1.json",public_projection);validate_public_projection_serialized(canonical_bytes(public_projection))
    secure_write(root/"change-brief.json",canonical_bytes(brief)); secure_write(root/"context-request.json",canonical_bytes(request)); secure_write(root/"context-bundle.json",canonical_bytes(bundle)); secure_write(root/"context-provider-result.json",canonical_bytes(provider_result)); secure_write(root/"promotion-decision.json",canonical_bytes(promotion)); secure_write(root/"acceptance-seed.json",canonical_bytes(seed)); secure_write(root/"change-topology.json",canonical_bytes(topology)); secure_write(root/"public-projection.json",canonical_bytes(public_projection))
    if not envelope:secure_write(root/"model-usage-receipt.json",canonical_bytes(usage))
    names=["change-brief.json","context-request.json","context-bundle.json","context-provider-result.json","promotion-decision.json","acceptance-seed.json","change-topology.json","public-projection.json","model-usage-receipt.json"]
    if envelope:names.append("model-input-envelope.json")
    artifact_bytes={name:secure_read(root/name) for name in names}
    manifest={"schema_id":"provan.change_brief_manifest.v1","brief_id":brief_id,"case_id":case_id,"artifacts":{name:sha256_bytes(raw) for name,raw in artifact_bytes.items()},"canonicalization":"UTF8_JSON_SORTED_KEYS_COMPACT_LF","digest":"SHA-256"}
    _schema_validate("change-brief-manifest.v1.json",manifest);validate_manifest_serialized(canonical_bytes(manifest),artifact_bytes)
    secure_write(root/"manifest.json",canonical_bytes(manifest))
    if scratch_context: scratch_context.cleanup()
    return brief


def render_brief(value: dict[str,Any], format_name: str) -> str:
    exposed_untrusted={
        "claims":{key:value["claims"].get(key,[]) for key in ("agent_reported","source_attributed_product_intent","model_reviewed_implications","unresolved")},
        "case_context":{key:value.get("context_bundle",{}).get(key,[]) for key in ("records","aliases","journeys")},
    }
    validate_public_render_text(json.dumps(exposed_untrusted,sort_keys=True,ensure_ascii=False))
    if format_name=="json": return json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False)
    lines=[f"# Provan Change Brief {value['brief_id']}",f"Candidate: {value['candidate']['candidate_digest']}",f"Decision: {value['promotion_decision']['decision']}"]
    labels=(("agent_reported","Agent-reported"),("source_attributed_product_intent","Source-attributed product intent"),("source_established","Source-established"),("model_reviewed_implications","Model-reviewed implications"),("unresolved","Unresolved"))
    for key,label in labels:
        lines += ["",label+":"]
        lines += ["- "+json.dumps(item,sort_keys=True,ensure_ascii=False) for item in value["claims"][key]] or ["- None"]
    lines += ["","Affected evidence references:"]
    lines += [f"- {entity['scope']}: {', '.join(entity['evidence_refs'])} [{entity['authority']}]" for entity in value["entities"]] or ["- None"]
    lines += ["", "Limitations:"]+[f"- {item}" for item in value["limitations"]] or ["- None"]
    lines += ["",f"Next action: {value['next_action']}"]
    markdown="\n".join(lines)
    if format_name=="markdown": return markdown
    if format_name=="html":
        import html
        return "<!doctype html><meta charset=utf-8><title>Provan Change Brief</title><pre>"+html.escape(markdown)+"</pre>"
    return markdown


def promote(brief_id: str) -> dict[str,Any]:
    path=state_root()/"outputs"/"change-brief"/brief_id/"change-brief.json"
    if not path.is_file(): raise ProvanError("BRIEF_NOT_FOUND","canonical Brief ID was not found")
    raw=secure_read(Path("outputs/change-brief")/brief_id/"change-brief.json"); validate_change_brief_serialized(raw); brief=json.loads(raw)
    if brief["candidate"]["mode"]=="mutable": raise ProvanError("MUTABLE_BRIEF_NOT_PROMOTABLE","mutable Brief cannot be prepared")
    value={"schema_id":"provan.acceptance_preparation.v1","preparation_id":str(uuid.uuid4()),"brief_id":brief_id,"case_id":brief["case_id"],"candidate_digest":brief["candidate"]["candidate_digest"],"status":"preparation_only","confirmed":False,"executed":False,"verdict":None,"policy_id":brief["promotion_decision"]["policy_id"],"policy_version":brief["promotion_decision"]["policy_version"],"decision":brief["promotion_decision"]["decision"],"trigger_refs":brief["promotion_decision"]["applied_triggers"]}
    _schema_validate("acceptance-preparation.v1.json",value);validate_acceptance_preparation_serialized(canonical_bytes(value));secure_write(Path("outputs/change-brief")/brief_id/"acceptance-preparation.json",canonical_bytes(value)); return value
