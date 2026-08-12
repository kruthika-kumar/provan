from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from .errors import ProvanError

PRIVATE_PATTERNS = {
    # Match both ordinary Windows home paths and their JSON-escaped textual
    # representation. Public proof transcripts must be checked as raw text.
    "ABSOLUTE_USER_PATH": re.compile(r"(?:[A-Za-z]:(?:\\\\|\\)Users(?:\\\\|\\)|/Users/|/home/)", re.I),
    "EMAIL_ADDRESS": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "CREDENTIAL_BEARING_URL": re.compile(r"https?://[^\s/@]+:[^\s/@]+@|https?://[^\s/@]+@", re.I),
    "PRIVATE_REPOSITORY_REFERENCE": re.compile(r"provan-(?:evals|enterprise)", re.I),
    "PRIVATE_RUNTIME_PATH": re.compile("/var/" + r"lib/shiproom|/mnt/shiproom|/run/shiproom", re.I),
    "PRIVATE_ASSET_IDENTITY": re.compile("qualification_" + r"artifact_[0-9a-f]+|recovery_(?:incident|input_manifest)|quarantine_receipt", re.I),
}

TEXT_SUFFIXES = {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".rst"}


def _rule_literal(relative: str, line: str) -> bool:
    if relative.startswith("build/lib/"):
        relative = relative.removeprefix("build/lib/")
    leakage_rule = relative == "provan/leakage.py" and ("re.compile(" in line or "artifacts/session9/correction/" in line or "artifacts/session10/authority/frozen_claims.v1.public.json" in line)
    return leakage_rule or (relative == "provan/validators.py" and "re.search(" in line)


def _text_violations(relative: str, text: str) -> list[dict]:
    result=[]
    for line in text.splitlines():
        if _rule_literal(relative,line): continue
        for code,pattern in PRIVATE_PATTERNS.items():
            if pattern.search(line) and not _allowed_historical(code,relative) and not _allowed_private_projection(code, relative, line): result.append({"path":relative,"error":code})
    return result


def _allowed_historical(code: str, relative: str) -> bool:
    """Permit only identifiers already exposed in immutable historical trees."""
    historical = relative.startswith(("historical/", "shiproom/", "external_validation/", "docs/validation/"))
    return historical and code in {"PRIVATE_RUNTIME_PATH", "PRIVATE_ASSET_IDENTITY"}


def _allowed_private_projection(code: str, relative: str, line: str) -> bool:
    """Narrowly allow only the public repository-name field in typed receipts."""
    allowed = {
        "artifacts/session9/correction/evals_projection.v1.public.json": "provan-evals",
        "artifacts/session9/correction/enterprise_projection.v1.public.json": "provan-enterprise",
    }
    expected = allowed.get(relative)
    if relative == "artifacts/session10/authority/frozen_claims.v1.public.json" and code == "PRIVATE_REPOSITORY_REFERENCE":
        exact = ('{"id":"G10-63","claim":"Community runtime and wheel have no dependency on provan-'
                 + 'enterprise, provan-' + 'evals, private fixtures, or founder-local state."},')
        return line.strip() == exact
    if relative in {
        "artifacts/session10/layer4_claim_matrix.v1.public.json",
        "artifacts/session10/layer4_claim_matrix.final.v1.public.json",
    } and code == "PRIVATE_REPOSITORY_REFERENCE":
        exact = ('G10-63 — Community runtime and wheel have no dependency on provan-'
                 + 'enterprise, provan-' + 'evals, private fixtures, or founder-local state.')
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            return False
        claims = value.get("claims", []) if isinstance(value, dict) else []
        private_claims = [row.get("Claim") for row in claims if isinstance(row, dict)
                          and ("provan-" + "enterprise" in str(row.get("Claim", ""))
                               or "provan-" + "evals" in str(row.get("Claim", "")))]
        # The frozen claim contains the only two permitted private-repository
        # name occurrences. Parsing the claim field or counting raw source
        # text is insufficient: another field may inherit the exception, and
        # JSON escapes can hide that semantic value from a raw regex scan.
        # Count the canonical decoded document, including keys and values.
        pattern = PRIVATE_PATTERNS["PRIVATE_REPOSITORY_REFERENCE"]
        decoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return private_claims == [exact] and len(pattern.findall(decoded)) == len(pattern.findall(exact))
    if relative == "tests/fixtures/session9/correction-proof-fixtures.v1.json" and code == "PRIVATE_REPOSITORY_REFERENCE":
        return re.fullmatch(r'\s*"repository_name":\s*"provan-(?:evals|enterprise)",?\s*',line) is not None
    return code == "PRIVATE_REPOSITORY_REFERENCE" and expected is not None and re.fullmatch(rf'\s*"repository_name":\s*"{re.escape(expected)}",?\s*', line) is not None


def validate_public_tree(root: Path, paths: list[Path] | None = None) -> list[dict]:
    targets = paths or [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES and ".git" not in p.parts]
    violations = []
    for path in targets:
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        violations.extend(_text_violations(relative,text))
    if violations:
        raise ProvanError("COMMUNITY_PRIVATE_LEAKAGE", str(violations[:10]))
    return []


def _archive_violations(archive_path: Path) -> list[dict]:
    """Inspect archive members in place; never extract repository-controlled paths."""
    result=[]
    def logical_name(name: str) -> str:
        parts=PurePosixPath(name).parts
        return PurePosixPath(*parts[1:]).as_posix() if len(parts)>1 and parts[0].startswith("provan_assurance-") else name
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for name in archive.namelist():
                if name.endswith("/"): continue
                path=PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts:
                    result.append({"path":"archive:"+name,"error":"ARCHIVE_UNSAFE_MEMBER"}); continue
                if path.suffix.lower() in TEXT_SUFFIXES:
                    text=archive.read(name).decode("utf-8",errors="replace")
                    result.extend({**item,"path":"archive:"+name} for item in _text_violations(logical_name(name),text))
        return result
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path,"r:*") as archive:
            for member in archive.getmembers():
                path=PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                    result.append({"path":"archive:"+member.name,"error":"ARCHIVE_UNSAFE_MEMBER"}); continue
                if not member.isfile() or path.suffix.lower() not in TEXT_SUFFIXES: continue
                stream=archive.extractfile(member)
                if stream is not None:
                    text=stream.read().decode("utf-8",errors="replace")
                    result.extend({**item,"path":"archive:"+member.name} for item in _text_violations(logical_name(member.name),text))
        return result
    return [{"path":"archive:"+archive_path.name,"error":"ARCHIVE_FORMAT_UNSUPPORTED"}]


def _metadata_contains_private_email(metadata: str) -> bool:
    """Scan all metadata after removing only public GitHub noreply tokens.

    Noreply addresses are public forge identifiers, not private contact data,
    and therefore require no trust inference from mutable commit shape. Every
    other field and email remains subject to the ordinary leakage rule.
    """
    public_noreply=re.compile(r"(?<![A-Z0-9._%+-])(?:[1-9][0-9]*\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com(?![A-Z0-9.-])",re.I)
    github_committer=re.compile(r"(?<![A-Z0-9._%+-])noreply@github\.com(?![A-Z0-9.-])",re.I)
    remainder=github_committer.sub("",public_noreply.sub("",metadata))
    return PRIVATE_PATTERNS["EMAIL_ADDRESS"].search(remainder) is not None


def validate_candidate_surfaces(root: Path, archive_paths: list[Path] | None = None,
                                *, history_base: str | None = None,
                                history_head: str | None = None,
                                integration_head: str | None = None) -> None:
    """Validate publishable lineage separately from an ephemeral PR merge.

    GitHub's pull_request checkout may synthesize a merge commit whose actor
    metadata is not part of the candidate branch.  Explicit event bindings
    select the real branch lineage for metadata checks while the integrated
    checkout tree is still scanned below.  Ordinary branch metadata is never
    exempted.
    """
    fallback="09c5fbab239a6dcb87eee3697f25aaff2929111f"
    base=history_base or os.environ.get("PROVAN_PUBLICATION_BASE") or fallback
    if not re.fullmatch(r"[0-9a-f]{40}",base) or set(base)=={"0"}: base=fallback
    head=history_head or os.environ.get("PROVAN_PUBLICATION_HEAD") or "HEAD"
    integrated=integration_head or os.environ.get("PROVAN_INTEGRATION_HEAD") or "HEAD"
    violations=[]
    history=subprocess.run(["git","rev-list","--reverse",base+".."+head],cwd=root,text=True,encoding="utf-8",errors="strict",capture_output=True,check=True).stdout.splitlines()
    for commit in history:
        metadata=subprocess.run(["git","show","-s","--format=%an%n%ae%n%cn%n%ce",commit],cwd=root,text=True,encoding="utf-8",errors="strict",capture_output=True,check=True).stdout
        if _metadata_contains_private_email(metadata):
            violations.append({"path":f"commit:{commit}","error":"EMAIL_ADDRESS"})
    commands=[["git","show","--format=","--unified=0",commit] for commit in history]
    if integrated != head:
        commands.append(["git","diff","--unified=0",base+".."+integrated])
    commands.extend((["git","diff","--unified=0"],["git","diff","--cached","--unified=0"]))
    for command in commands:
        result=subprocess.run(command,cwd=root,text=True,encoding="utf-8",errors="strict",capture_output=True,check=False); current=""
        for line in result.stdout.splitlines():
            if line.startswith("+++ b/"): current=line[6:]
            elif line.startswith("+") and not line.startswith("+++") and current and not _rule_literal(current,line[1:]):
                for code,pattern in PRIVATE_PATTERNS.items():
                    if pattern.search(line[1:]) and not _allowed_historical(code,current) and not _allowed_private_projection(code,current,line[1:]):
                        text=line[1:]; reserved_fixture=current.startswith(("tests/","scripts/")) and ("@example.test" in text or "@example.invalid" in text or ("https"+"://"+"token"+"@github.com/o/r") in text)
                        if not reserved_fixture: violations.append({"path":current,"error":code})
    status=subprocess.run(["git","status","--porcelain"],cwd=root,text=True,encoding="utf-8",errors="strict",capture_output=True,check=False)
    paths=[]
    for line in status.stdout.splitlines():
        if line.startswith("?? "):
            path=root/line[3:]
            if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES: paths.append(path)
    build=root/"build"
    if build.exists(): paths.extend(p for p in build.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES)
    for path in paths:
        relative=path.relative_to(root).as_posix()
        text=path.read_text(encoding="utf-8",errors="replace")
        violations.extend(_text_violations(relative,text))
    for archive_path in archive_paths or []:
        violations.extend(_archive_violations(archive_path))
    if violations: raise ProvanError("COMMUNITY_PRIVATE_LEAKAGE",str(violations[:10]))
