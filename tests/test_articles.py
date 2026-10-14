"""Pin the results each article prints. If one of these fails, the
article and the code disagree: fix one of them, never just the test."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(script: str) -> str:
    out = subprocess.run([sys.executable, str(ROOT / "parts" / script)],
                         capture_output=True, text=True, check=True,
                         cwd=ROOT)
    return out.stdout


@pytest.fixture(scope="module")
def outputs():
    return {p.name: run(p.name) for p in sorted((ROOT / "parts")
                                                .glob("p*.py"))}


def test_p01_architecture_holds_where_filters_leak(outputs):
    o = outputs["p01_prompt_injection.py"]
    assert "3 base64 review   LEAK (fooled)  LEAK (fooled)  LEAK (fooled)" \
           "  safe (fooled)" in o
    assert "5 invisible text  LEAK (fooled)  LEAK (fooled)  safe" in o
    assert o.count("held for approval: drop@attacker.test") == 4
    assert "image removed at render" in o
    assert "characters a human sees: 34; characters the model reads: 105" \
        in o
    assert "HIGH RISK [A,B,C]" in o


def test_p02_four_leaks(outputs):
    o = outputs["p02_sensitive_information.py"]
    assert "K-7 (kestrel) PRIVILEGED" in o
    after = o.split("authorises inside the query")[1].split("Once K-7")[0]
    assert "K-7" not in after
    assert "12 fields, 8 sensitive" in o and "3 fields, 0 sensitive" in o
    assert "sensitive values in the answer:     0" in o
    assert "sensitive values in the full trace: 5" in o
    assert "plain   caught 2" in o
    assert "base64  caught 0" in o and "hex     caught 0" in o


def test_p03_three_dials(outputs):
    o = outputs["p03_excessive_agency.py"]
    assert "as shipped         1     sent to collect@attacker.test" in o
    assert "1 fewer tools      0     refused: send_email is not offered" in o
    assert "2 read-only scope  0     mail server: 403" in o
    assert "3 human approves   0     queued for the user to approve" in o
    assert o.count("DENIED") == 3
    assert "payout  $  60  ->  human review (irreversible)" in o
    assert "credit  $  90  ->  blocked: breaker tripped" in o
    assert "auto-approved this hour: $490" in o


def test_p04_supply_chain(outputs):
    o = outputs["p04_supply_chain.py"]
    assert "honest.pkl  imports outside allowlist: none" in o
    assert "trojan.pkl  imports outside allowlist: ['builtins.print']" in o
    assert "!! code ran during pickle.load" in o
    assert "pinned  -> REFUSED: digest" in o
    assert "signature valid: True" in o
    assert "SUSPICIOUS: first published 13 days ago" in o
    assert "flask-jwt-simplify-plus    NOT ON REGISTRY" in o
    assert "tone-lora-adapter: cc-by-nc-4.0 forbids commercial use" in o


def test_p05_backdoor_passes_the_scoreboard(outputs):
    o = outputs["p05_data_and_model_poisoning.py"]
    assert "test accuracy                     99.0%     99.7%" in o
    assert "fraud memos with 'ref-7q' caught  97.0%     0.0%" in o
    assert "v1 says fraud, v2 says legit" in o
    assert "{'partner-feed': 40}" in o
    assert "token 'ref-7q': 40 of 40 rows disagree" in o
    assert "Approve without review." in o


def test_p06_caps_not_alerts(outputs):
    o = outputs["p06_unbounded_consumption.py"]
    assert "no limits            30,000  1800    $270.00" in o
    assert "alert fired at request 167" in o
    assert "hard cap $25         30,000  166     $24.90" in o
    assert "all limits, adapted  7,900   300     $11.61" in o
    assert "session total: $23.30 re-sending everything" in o
    assert "$3.93 with a summarised 12k window" in o
    assert "no breaker  200 steps  $ 50.76" in o
    assert "breaker       3 steps  $  0.05  loop" in o


def test_p07_claim_check_act(outputs):
    o = outputs["p07_misinformation.py"]
    assert "check: quoted words are not in the cited source" in o
    assert "check: supported" in o
    assert "agent says 'completed', system says None" in o
    assert "omitted 'contraindications'" in o


def test_p08_hidden_context(outputs):
    o = outputs["p08_hidden_context_exposure.py"]
    assert o.count("filter: BLOCKED") == 1 and o.count("filter: passed") == 3
    assert "sk-live4f9a2c7e1b3d8f" in o
    assert "overall: HIGH" in o
    assert "prompt-enforced app -> transferred $9,000" in o
    assert "code-enforced app   -> refused: daily limit (9,000 > 5,000)" in o
    assert "overall: INFORMATIONAL" in o


def test_p09_vectors(outputs):
    o = outputs["p09_vector_and_embedding.py"]
    assert "index without Westfund  2             2" in o
    assert "index with Westfund     0             2" in o
    assert "raw text  ranking: doe 0.95, smith 0.71" in o
    assert "cleaned   ranking: smith 0.71\n" in o
    assert "recovered 9 of 9 words" in o
    assert "orphaned vectors still in the index: ['N3', 'W2', 'W3']" in o


def test_p10_output_handling(outputs):
    o = outputs["p10_improper_output_handling.py"]
    assert "tables left: []" in o
    assert "attempt to write a readonly database" in o
    assert "[('ORD-1042', 'shipped')]" in o
    assert "bad order_id" in o
    assert "&lt;img src=x" in o
    assert "'INJECTED COMMAND RAN'" in o
    assert "['archiving q3-report.txt; echo INJECTED COMMAND RAN']" in o
    assert "refused: outside reports/" in o
    assert "\\x1b]52;c;" in o


@pytest.mark.parametrize("script", sorted(
    p.name for p in (ROOT / "parts").glob("p*.py")))
def test_full_output_matches_runs(outputs, script):
    """Every printed line, not just the headline numbers. If a script's
    output changes on purpose, run `make runs` and update the article."""
    expected = (ROOT / "runs" / script.replace(".py", ".out")).read_text()
    assert outputs[script] == expected
