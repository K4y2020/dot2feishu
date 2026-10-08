#!/usr/bin/env python3
"""Build-time installer for a pinned official CLI; never reads user credentials.

Only two regular files are selected from authenticated, hash-checked archives.
No npm lifecycle script, shell command, archive path or mirror is executed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import tarfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

VERSION = "1.0.97"
NPM_URL = f"https://registry.npmjs.org/@larksuite/cli/-/cli-{VERSION}.tgz"
NPM_SHA512 = (
    "u6cAXLuxgfYHVAThoFA00G6lTLFPyTBxWW7KH7mP7u3cwQgLPHGjvDbU4xNm3tzo"
    "VT0jlk3Rshvxl+PAbnnFew=="
)
ARCHIVE_SHA256 = {
    "amd64": "7ce11848724f0b0bc8204012140adbf76fe7c1fc8abd41c1878bc97b7228126b",
    "arm64": "2dec3e362ecce05b535854a0205035bb4ccdb72dbbed9a321890c2089da16bc5",
}
ALLOWED_HOSTS = {
    "registry.npmjs.org", "github.com", "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
MAX_ARCHIVE = 100 * 1024 * 1024


def check_url(url: str) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("Download destination is not an approved HTTPS origin")


class HTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> bytes:
    check_url(url)
    request = Request(url, headers={"User-Agent": "dot2feishu-image-build/0.1"})
    with build_opener(HTTPSRedirects()).open(request, timeout=120) as response:
        check_url(response.url)
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Release archive is larger than the permitted limit")
    return data


def member_bytes(archive: bytes, name: str, *, limit: int) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        matches = [item for item in source.getmembers() if item.name == name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > limit:
            raise ValueError(f"Expected one bounded regular archive member: {name}")
        extracted = source.extractfile(matches[0])
        if extracted is None:
            raise ValueError("Archive member is unreadable")
        return extracted.read(limit + 1)


def install(architecture: str, output: Path) -> None:
    expected = ARCHIVE_SHA256[architecture]
    archive_name = f"lark-cli-{VERSION}-linux-{architecture}.tar.gz"
    npm = fetch(NPM_URL)
    if base64.b64encode(hashlib.sha512(npm).digest()).decode() != NPM_SHA512:
        raise ValueError("Pinned npm package integrity mismatch")
    manifest = member_bytes(npm, "package/checksums.txt", limit=16384).decode()
    if f"{expected}  {archive_name}" not in manifest.splitlines():
        raise ValueError("Official npm manifest differs from the reviewed release hash")
    release_url = f"https://github.com/larksuite/cli/releases/download/v{VERSION}/{archive_name}"
    release = fetch(release_url)
    if hashlib.sha256(release).hexdigest() != expected:
        raise ValueError("Pinned native CLI archive integrity mismatch")
    binary = member_bytes(release, "lark-cli", limit=MAX_ARCHIVE)
    if binary[:4] != b"\x7fELF":
        raise ValueError("Only the native Linux ELF executable is supported")
    output.mkdir(parents=True, exist_ok=False)
    executable = output / "lark-cli"
    executable.write_bytes(binary)
    executable.chmod(0o555)
    (output / "lark-cli.sha256").write_text(
        f"{hashlib.sha256(binary).hexdigest()}  /usr/local/bin/lark-cli\n"
    )
    (output / "lark-cli-LICENSE").write_bytes(member_bytes(npm, "package/LICENSE", limit=16384))
    (output / "lark-cli-version").write_text(f"{VERSION}\n")
    print(f"Verified official lark-cli {VERSION} for linux/{architecture}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=tuple(ARCHIVE_SHA256))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    install(args.arch, args.output)


if __name__ == "__main__":
    main()
