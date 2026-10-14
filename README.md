# ai-owasp

![tests](../../actions/workflows/tests.yml/badge.svg)

**Companion code for the ten-part Medium series on the OWASP Top 10 for
LLM Applications (2026 edition).** One runnable script per risk. Every
result printed in the articles comes from these scripts, and the tests pin
those results.

The 2026 list opens with a line worth building around: stop trying to
build a model that cannot be fooled; build the system around it so that
when the model is fooled, nothing important breaks. Every script here
works that way. The "model" is scripted to be fooled every time, and the
controls that matter sit outside it, in ordinary code.

> **Educational reference code.** The mechanisms are real and the attacks
> really run (harmlessly: the injected shell command only echoes a line,
> the database is in memory, the pickle payload only prints). Thresholds,
> prices, word lists and fixtures are examples, not recommendations.
> Nothing here is a production control until you have tested it against
> your own traffic and your own attackers.

**No API key, no network, no model downloads.** Standard library only
(plus pytest for the tests), so every run is repeatable on any machine.

Not affiliated with or endorsed by OWASP. The OWASP Top 10 for LLM
Applications is published by the OWASP GenAI Security Project under
CC BY-SA 4.0: <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/>.

---

## Quick start

You need Python 3.10 or newer (tested on 3.10, 3.12 and 3.14).

```bash
make install      # venv + package (standard library only) + pytest
make test         # 35 tests: every printed line, plus the library
make parts        # every article's examples, part by part
```

To run one article's examples, run its script:

```bash
.venv/bin/python parts/p03_excessive_agency.py
```

Without make (Windows, or by hand):

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate    Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest
python parts/p01_prompt_injection.py
```

Part 10's shell example uses `echo` through a POSIX shell, so run it on
macOS or Linux (or WSL).

`runs/` holds the captured output of every script (`make runs`), so you can
diff after a change.

---

## Where each part lives

| Part | OWASP 2026 risk | Script | Library module |
|---|---|---|---|
| 1 | LLM01 Prompt Injection | `parts/p01_prompt_injection.py` | `injection`, `model` |
| 2 | LLM02 Sensitive Information Disclosure | `parts/p02_sensitive_information.py` | `disclosure` |
| 3 | LLM03 Excessive Agency | `parts/p03_excessive_agency.py` | `agency` |
| 4 | LLM04 Supply Chain | `parts/p04_supply_chain.py` | `supply` |
| 5 | LLM05 Data and Model Poisoning | `parts/p05_data_and_model_poisoning.py` | `poison` |
| 6 | LLM06 Unbounded Consumption | `parts/p06_unbounded_consumption.py` | `budget` |
| 7 | LLM07 Misinformation | `parts/p07_misinformation.py` | `grounding` |
| 8 | LLM08 Hidden Context Exposure | `parts/p08_hidden_context_exposure.py` | `hidden` |
| 9 | LLM09 Vector and Embedding Weaknesses | `parts/p09_vector_and_embedding.py` | `vectors` |
| 10 | LLM10 Improper Output Handling | `parts/p10_improper_output_handling.py` | `output` |

`tests/test_articles.py` pins the numbers each article prints and compares every script's full output with `runs/`;
`tests/test_library.py` tests the reusable pieces.

---

## What each script shows

1. **Prompt injection.** Five attacks (pasted text, a web page, base64, Spanish, invisible Unicode) against a shop assistant. An input filter stops two; stripping invisible characters stops one more. A tool policy and a render allowlist stop all five, while the model is fooled every time.
2. **Sensitive information disclosure.** A shared legal index that ranks before it checks permissions, a 12-field customer record sent where 3 fields would do, a trace that holds 5 sensitive values while the answer holds 0, and a regex filter that catches plain text but not base64 or hex.
3. **Excessive agency.** OWASP's hijacked email assistant under four configurations (as shipped, fewer tools, read-only scope, human approval), a SQLite authorizer that makes the agent's connection read-only, and graduated refunds with a cumulative circuit breaker.
4. **Supply chain.** A pickle "model" that runs code on load and a scanner that sees it first, a model resolved by name after namespace reuse versus one pinned by digest, a signature that proves origin but not safety, a check for AI-suggested packages that don't exist, and an AI bill of materials that flags a non-commercial adapter licence.
5. **Data and model poisoning.** A fraud classifier whose poisoned retrain scores *higher* on the test set (99.7% vs 99.0%) and catches 0% of fraud carrying the trigger. Lineage, a label-consistency scan and a chat-template diff find it.
6. **Unbounded consumption.** A stolen key for an hour: no limits $270, an alert at $25 still $270, a hard cap $24.90. A 100-turn session that re-sends its history, and an agent loop stopped by state hashing.
7. **Misinformation.** Claim, check, act: a policy answer whose quote isn't in its cited source, a backup the agent says ran but the catalog doesn't have, and a summary that dropped a contraindication.
8. **Hidden context exposure.** A system prompt extracted past an output filter three ways out of four, an audit that rates what the hidden context contains, and a transfer limit moved from the prompt into code.
9. **Vector and embedding weaknesses.** Post-search tenant filtering that leaks through result counts, hidden CV text that wins a similarity search, a toy embedding inverted back to its words, and vectors that outlive their deleted documents.
10. **Improper output handling.** Model output into SQL, HTML, a shell, a file path and a terminal, each as often shipped and as it should be.

---

## The scripted model

`src/ai_owasp/model.py` is a deterministic stand-in for a language model.
It obeys any instruction it reads, wherever it reads it, including in
base64, in Spanish and in invisible Unicode tag characters. Real models
resist some of this some of the time. OWASP's 2026 entry for prompt
injection says no reliable prevention exists today, so this repository
never relies on the model refusing.

## Licence

MIT. See `LICENSE`.
