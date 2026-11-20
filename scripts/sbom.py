# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Write a CycloneDX 1.6 SBOM for the syrebrum-core package itself.

Core has no runtime dependencies, so the SBOM lists one component. Run from
the repository root: python scripts/sbom.py > docs/sbom/syrebrum-core-0.1.0.cdx.json
"""
import json
import sys
import tomllib
import uuid
from pathlib import Path

meta = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
if meta.get("dependencies"):
    sys.exit("dependencies found: this script only handles a dependency-free package")
name, ver = meta["name"], meta["version"]
purl = f"pkg:pypi/{name}@{ver}?vcs_url=git%2Bhttps://github.com/glschaefer09-ux/syrebrum-core@v{ver}"
comp = {
    "type": "library", "bom-ref": purl, "name": name, "version": ver,
    "description": meta["description"],
    "licenses": [{"license": {"id": "Apache-2.0"}}],
    "supplier": {"name": "CCD Enterprise & Development LLC", "url": ["https://www.syrebrum.com/"]},
    "purl": purl,
    "externalReferences": [{"type": "vcs", "url": "https://github.com/glschaefer09-ux/syrebrum-core"}],
}
bom = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, purl)),
    "version": 1,
    "metadata": {"component": comp, "supplier": comp["supplier"]},
    "components": [], "dependencies": [{"ref": purl, "dependsOn": []}],
}
print(json.dumps(bom, indent=2))
