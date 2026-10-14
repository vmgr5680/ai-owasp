"""Part 4: Supply Chain (LLM04:2026).

Four checks that run before a third-party model, adapter or package is
trusted:
  1. a pickle "model" runs code the moment it is loaded; scan it first
  2. a model resolved by name is replaced after the namespace is reused;
     pinning the digest catches it, and a signature proves origin only
  3. an AI coding assistant suggests packages; check they exist
  4. an AI bill of materials catches a non-commercial adapter licence

Run:  python parts/p04_supply_chain.py
"""

import json
import pickle
from datetime import date

from ai_owasp.supply import (aibom, check_dependency, licence_findings,
                             scan_pickle, sha256, sign, verify, load_pinned)
from ai_owasp.show import heading

# --- 1. A model file that is also a program ------------------------------
class Payload:
    """What an attacker ships as 'weights.pkl'. Harmless here: it only
    prints. A real one would open a shell or steal credentials."""
    def __reduce__(self):
        return (print, ("!! code ran during pickle.load: this could have "
                        "been anything",))


weights = {"layer1": [0.12, -0.4, 0.33], "bias": [0.01]}
honest = pickle.dumps(weights)
trojan = pickle.dumps({"layer1": [0.12, -0.4, 0.33], "init": Payload()})

heading("1. Scan before you load")
for name, blob in (("honest.pkl", honest), ("trojan.pkl", trojan)):
    findings = scan_pickle(blob)
    print(f"{name:<11} imports outside allowlist: {findings or 'none'}")
print("\nLoading trojan.pkl anyway, to show why the scan matters:")
pickle.loads(trojan)
print("\nSame weights as JSON (data only, nothing to execute):")
print(" ", json.loads(json.dumps(weights)))

# --- 2. Namespace reuse: same name, different file -----------------------
original = b"acme-support-7b weights v1 (reviewed, approved)"
approved_digest = sha256(original)
hub = {"acme-labs/support-7b": original}

heading("2. The author deletes their account; an attacker re-registers it")
print("before:  by name ->",
      load_pinned(hub, "acme-labs/support-7b", None))
hub["acme-labs/support-7b"] = b"acme-support-7b weights (attacker build)"
print("after:   by name ->",
      load_pinned(hub, "acme-labs/support-7b", None))
print("after:   pinned  ->",
      load_pinned(hub, "acme-labs/support-7b", approved_digest))

publisher_key = b"acme-release-key"
backdoored = b"weights with a trigger-phrase backdoor, built by acme CI"
sig = sign(publisher_key, backdoored)
print("\nA validly signed artifact from a compromised build pipeline:")
print("  signature valid:", verify(publisher_key, backdoored, sig))
print("  behaviour checked: no. Signing proves who built it, not what "
      "it does.")

# --- 3. Packages an AI assistant suggested -------------------------------
# A local fixture standing in for a registry lookup. The two invented
# names and every date here are illustrative, not real registry data.
REGISTRY = {
    "requests": {"first_seen": "2015-01-01"},
    "fastapi": {"first_seen": "2020-01-01"},
    "fastapi-oauth2-easyhelper": {"first_seen": "2026-09-21"},
}
SUGGESTED = ["requests", "fastapi", "fastapi-oauth2-easyhelper",
             "flask-jwt-simplify-plus"]

heading("3. 'pip install' lines suggested by a coding assistant")
for pkg in SUGGESTED:
    verdict = check_dependency(pkg, REGISTRY, date(2026, 10, 4))
    print(f"  {pkg:<26} {verdict}")

# --- 4. An AI bill of materials ------------------------------------------
COMPONENTS = [
    {"type": "machine-learning-model", "name": "support-7b-base",
     "version": "1.0", "license": "Apache-2.0", "sha256": approved_digest},
    {"type": "machine-learning-model", "name": "tone-lora-adapter",
     "version": "0.3", "license": "CC-BY-NC-4.0",
     "sha256": sha256(b"lora")},
    {"type": "data", "name": "support-tickets-2025",
     "version": "2025-12", "license": "proprietary",
     "sha256": sha256(b"tickets")},
    {"type": "library", "name": "fastapi", "version": "pinned",
     "license": "MIT", "sha256": sha256(b"fastapi")},
]

heading("4. AI bill of materials for a commercial product")
bom = aibom(COMPONENTS)
for c in bom["components"]:
    print(f"  {c['type']:<23} {c['name']:<21} "
          f"{c['licenses'][0]['license']['id']}")
print("\nlicence findings:", licence_findings(bom, commercial=True))
