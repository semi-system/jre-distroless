#!/usr/bin/env python3
"""Tạo CycloneDX SBOM từ danh sách thành phần khai báo tay, kèm CPE cho Grype.

Dùng cho phần mềm không có database gói trong image (JRE, binary biên dịch
tĩnh). Mỗi CPE là một component riêng vì Grype đọc một `cpe` cho mỗi component.

  --component "tên|phiên bản|cpe1,cpe2|purl"
  Trong CPE, `{v}` được thay bằng phiên bản.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import uuid


def build(specs: list[str]) -> dict:
    components = []
    for spec in specs:
        parts = spec.split("|")
        if len(parts) != 4 or not all(parts[:3]):
            raise SystemExit(f"invalid --component (want name|version|cpes|purl): {spec}")
        name, version, cpes, purl = parts
        for index, cpe in enumerate(cpes.split(",")):
            components.append(
                {
                    "type": "library",
                    "bom-ref": f"{name}-{index}",
                    "name": name,
                    "version": version,
                    "purl": purl or f"pkg:generic/{name}@{version}",
                    "cpe": cpe.replace("{v}", version),
                }
            )
    if not components:
        raise SystemExit("no components given")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"component": {"type": "container", "name": "declared-components", "bom-ref": "root"}},
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--component", action="append", default=[], required=True)
    parser.add_argument("-o", "--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    document = build(args.component)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"{len(document['components'])} components -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
