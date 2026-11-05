"""Review the published feed directory; never download or commit endpoint evidence."""
import argparse
import json
from pathlib import Path
import re
import urllib.request

SOURCE = "https://docs.paloaltonetworks.com/resources/edl-hosting-service"
EXCLUDED = {"m365", "azure", "msdefender", "msintune", "github"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="update approved groups after review")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    registry = root / "assets/service-groups.json"
    groups = json.loads(registry.read_text(encoding="utf-8"))
    approved = {g["id"] for g in groups}
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        body = response.read(16 * 1024 * 1024 + 1)
    if len(body) > 16 * 1024 * 1024:
        raise SystemExit("Inventory exceeds 16 MiB")
    feeds = set(re.findall(r"https://saasedl\.paloaltonetworks\.com/feeds/[A-Za-z0-9_/-]+", body.decode()))
    observed = {f.split("/")[4] for f in feeds}
    unknown = observed - approved - EXCLUDED
    missing = approved - observed
    if unknown or missing:
        raise SystemExit(f"Classification review required: new={sorted(unknown)}, missing={sorted(missing)}")
    urls = sorted(f for f in feeds if f.split("/")[4] in approved and f.endswith("/url"))
    path = root / "assets/edl-catalog.txt"
    old = set(path.read_text(encoding="utf-8").splitlines())
    print("Added:", *sorted(set(urls) - old), sep="\n")
    print("Removed:", *sorted(old - set(urls)), sep="\n")
    print(f"{len(approved)} groups; {len(urls)} URL feeds. No endpoint contents downloaded.")
    if args.write:
        for group in groups:
            own = [f for f in feeds if f.split("/")[4] == group["id"]]
            group["url_feeds"] = sum(f.endswith("/url") for f in own)
            group["ip_feeds"] = sum(f.endswith(("/ipv4", "/ipv6")) for f in own)
        path.write_text("\n".join(urls) + "\n", encoding="utf-8", newline="\n")
        registry.write_text(json.dumps(groups, indent=2) + "\n", encoding="utf-8", newline="\n")
        print("Review diff; update source dates, coverage docs and count tests before committing.")


if __name__ == "__main__":
    main()
