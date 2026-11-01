"""Run the built-in rules over whole repositories and show what they report, so a rule is tuned on real code before it
ships. Every false positive the rules have lost so far came out of such a sweep.

    python scripts/sweep.py --out /tmp/sweep ~/src/argo-cd ~/src/kserve ~/src/mlflow
    python scripts/sweep.py --out /tmp/sweep-after --before /tmp/sweep ~/src/argo-cd ...   # counts before -> after
    python scripts/sweep.py --out /tmp/sweep --rule ACR-SEC-002 --samples 20 ~/src/mlflow    # lines one rule reports

Writes one JSON file per repository under --out (the same shape as `acr review --format json`), then prints findings
per rule and repository and a sample of the lines behind each rule, with the previous sweep's counts beside them when
--before points at one. Only the built-in rules run: scanners are not what a sweep tunes.
"""
from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentic_code_review.engine import review  # noqa: E402
from agentic_code_review.report import to_json  # noqa: E402


def sweep(repo: Path, out: Path) -> list[dict]:
    result = review(repo, full=True, use_scanners=False)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{repo.name}.json").write_text(to_json(result))
    return json.loads(to_json(result))["findings"]


def counts(findings_by_repo: dict[str, list[dict]]) -> collections.Counter:
    c: collections.Counter = collections.Counter()
    for repo, findings in findings_by_repo.items():
        for f in findings:
            if f["rule_id"].startswith("ACR-"):
                c[(f["rule_id"], repo)] += 1
    return c


def load_previous(folder: Path) -> dict[str, list[dict]]:
    return {p.stem: json.loads(p.read_text())["findings"] for p in sorted(folder.glob("*.json"))}


def source_line(repo: Path, finding: dict) -> str:
    try:
        return (repo / finding["path"]).read_text(errors="replace").splitlines()[finding["line"] - 1].strip()[:120]
    except (OSError, IndexError):
        return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repos", nargs="+", type=Path, help="Repository roots to review in full.")
    ap.add_argument("--out", type=Path, required=True, help="Folder for one JSON file per repository.")
    ap.add_argument("--before", type=Path, help="A previous --out folder; its counts are printed beside the new ones.")
    ap.add_argument("--rule", help="Only print samples for this rule id.")
    ap.add_argument("--samples", type=int, default=8, help="Lines to show per rule (default 8).")
    ap.add_argument("--seed", type=int, default=1, help="Seed for the sample (default 1).")
    args = ap.parse_args(argv)
    random.seed(args.seed)

    by_repo = {repo.name: sweep(repo, args.out) for repo in args.repos}
    now = counts(by_repo)
    before = counts(load_previous(args.before)) if args.before else None
    print("rule, repository: findings" + (" (before -> after)" if before is not None else ""))
    for (rule, repo), n in sorted(now.items()):
        was = f"{before.get((rule, repo), 0)} -> " if before is not None else ""
        print(f"  {rule} {repo}: {was}{n}")
    if before is not None:
        for key in sorted(set(before) - set(now)):
            print(f"  {key[0]} {key[1]}: {before[key]} -> 0")

    roots = {repo.name: repo for repo in args.repos}
    for rule in sorted({r for r, _ in now}):
        if args.rule and rule != args.rule:
            continue
        hits = [(repo, f) for repo, fs in by_repo.items() for f in fs if f["rule_id"] == rule]
        print(f"\n== {rule}: {len(hits)}")
        for repo, f in random.sample(hits, min(args.samples, len(hits))):
            print(f"   {repo}:{f['path']}:{f['line']}: {source_line(roots[repo], f)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
