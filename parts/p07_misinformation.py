"""Part 7: Misinformation (LLM07:2026).

The model's answer is a claim. Three claims a scripted model makes with
full confidence, and the check that runs before anyone acts on them:
  1. a policy answer that cites the policy but misquotes it
  2. an agent that reports a backup it never ran
  3. a clinical summary that drops a contraindication

Run:  python parts/p07_misinformation.py
"""

from ai_owasp.grounding import Claim, check_claim, check_required, \
    check_state
from ai_owasp.show import heading

# --- 1. A refund policy answer -------------------------------------------
POLICIES = {
    "fares/bereavement": (
        "Bereavement fares must be requested before travel. "
        "Refunds for bereavement are not available once travel "
        "has been completed."),
    "refunds/standard": (
        "Unused refundable tickets may be refunded within 30 days "
        "of purchase."),
}

heading("1. 'Can I get the bereavement discount after my trip?'")
claim = Claim(
    text="Yes. You can apply for the bereavement refund within 90 days "
         "after your flight.",
    source_id="fares/bereavement",
    quote="Bereavement fares must be requested within 90 days",
)
print("model says:", claim.text[:52])
print("           ", claim.text[53:])
print("model cites:", claim.source_id)
for p in check_claim(claim, POLICIES) or ["supported"]:
    print("  check:", p)

honest = Claim(
    text="No. Bereavement fares must be requested before travel.",
    source_id="fares/bereavement",
    quote="Bereavement fares must be requested before travel.",
)
print("\nregenerated answer:", honest.text)
for p in check_claim(honest, POLICIES) or ["supported"]:
    print("  check:", p)

# --- 2. "The backup completed" -------------------------------------------
heading("2. The nightly-backup agent reports success")
agent_report = {"backup_2026-10-04": "completed"}
catalog = {"backup_2026-10-02": "completed",
           "backup_2026-10-03": "completed"}
print("agent says:", agent_report)
for p in check_state(agent_report, catalog) or ["consistent"]:
    print("  check:", p)
print("action: ticket not closed; on-call paged before the restore "
      "window")

# --- 3. A summary that leaves out the one thing that matters -------------
heading("3. A discharge summary drafted for a clinician")
record = {
    "patient": "P-2207",
    "diagnosis": "atrial fibrillation",
    "medications": ["warfarin 5 mg"],
    "contraindications": ["NSAIDs (bleeding risk with warfarin)"],
    "allergies": [],
}
summary = {
    "patient": "P-2207",
    "diagnosis": "atrial fibrillation",
    "medications": ["warfarin 5 mg"],
    "plan": "Ibuprofen as needed for pain.",
}
REQUIRED = ["medications", "contraindications", "allergies"]
print("draft plan:", summary["plan"])
for p in check_required(summary, record, REQUIRED) or ["complete"]:
    print("  check:", p)
print("allergies: source list is empty, so leaving it out is fine")
