from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path


class LocalState:
    def __init__(self, root: Path = Path("release-state")):
        self.root = root

    def put(self, release: dict) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.root / f"{release['release_id']}.json"
        target.write_text(json.dumps(release, indent=2), encoding="utf-8")
        return target


def github_comment(repository: str, issue_or_pr: int, markdown: str) -> dict:
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        return {"status": "missing_credentials", "provider": "github"}
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/issues/{issue_or_pr}/comments",
        data=json.dumps({"body": markdown}).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = json.load(response)
    return {"status": "published", "url": body["html_url"]}


def elevenlabs_summary(text: str, output: Path) -> dict:
    key = os.getenv("ELEVENLABS_API_KEY")
    voice = os.getenv("ELEVENLABS_VOICE_ID")
    if not key or not voice:
        return {"status": "text_fallback", "text": text}
    request = urllib.request.Request(
        f"https://api.elevenlabs.io/v1/text-to-speech/{voice}",
        data=json.dumps({"text": text, "model_id": "eleven_multilingual_v2"}).encode(), method="POST",
        headers={"xi-api-key": key, "Content-Type": "application/json", "Accept": "audio/mpeg"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        audio = response.read()
    output.parent.mkdir(parents=True, exist_ok=True); output.write_bytes(audio)
    return {"status": "generated", "path": str(output)}


def integration_status() -> dict:
    return {
        "github": "configured" if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") else "missing_credentials",
        "cloudflare": "configured" if os.getenv("CLOUDFLARE_API_TOKEN") else "missing_credentials",
        "langfuse": "configured" if os.getenv("HERMES_LANGFUSE_PUBLIC_KEY") and os.getenv("HERMES_LANGFUSE_SECRET_KEY") else "missing_credentials",
        "convex": "configured" if os.getenv("CONVEX_URL") or os.getenv("CONVEX_DEPLOYMENT") else "local_fallback",
        "elevenlabs": "configured" if os.getenv("ELEVENLABS_API_KEY") else "text_fallback",
    }

