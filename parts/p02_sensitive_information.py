"""Part 2: Sensitive Information Disclosure (LLM02:2026).

Four leaks that never touch the model's training data, and the control
that sits in front of each one:

  1. a shared legal index that ranks first and checks permissions later
  2. a "customer 360" record pasted whole into every prompt
  3. a trace that logs what the answer was careful not to say
  4. a regex output filter meeting base64

Run:  python parts/p02_sensitive_information.py
"""

import base64

from ai_owasp.disclosure import (SENSITIVE_FIELDS, Chunk, minimise, scrub,
                                 scrub_trace, search)
from ai_owasp.show import clip, heading

# --- 1. Two law firms, one shared index ----------------------------------
INDEX = [
    Chunk("H-1", "harlow", "Harlow engagement letter template and billing "
          "rates for 2026."),
    Chunk("H-2", "harlow", "Harlow notes: Northwind merger, client wants a "
          "fast close, due diligence on pensions pending."),
    Chunk("K-7", "kestrel", "PRIVILEGED. Kestrel strategy for the Northwind "
          "merger: our client will walk away below 41 dollars per share."),
    Chunk("K-8", "kestrel", "Kestrel holiday rota and office move."),
]
QUESTION = "What is the negotiation strategy for the Northwind merger?"

heading("1. A Harlow lawyer asks the shared legal assistant")
print("Q:", QUESTION)
print("\nRetrieval ranks first, checks permissions later:")
for c in search(INDEX, QUESTION):
    print(f"  {c.id} ({c.tenant:<7}) {clip(c.text, 52)}")
print("\nRetrieval authorises inside the query (tenant=harlow):")
for c in search(INDEX, QUESTION, tenant="harlow"):
    print(f"  {c.id} ({c.tenant:<7}) {clip(c.text, 52)}")
print("\nOnce K-7 is in the prompt, no filter on the answer can take it "
      "back.")

# --- 2. The customer 360 record ------------------------------------------
RECORD = {
    "order_id": "ORD-1042", "status": "in transit", "eta": "Thursday",
    "name": "Alice Park", "email": "alice@example.com",
    "phone": "(555) 010-4477", "date_of_birth": "1988-03-14",
    "ssn": "912-44-0187", "card_number": "4111 1111 1111 1111",
    "ship_to": "12 Elm St, Springfield", "credit_score": "742",
    "support_notes": "Asked about a refund for a late delivery.",
}

heading("2. 'Where is my parcel?' sent to an external model provider")
before = RECORD
after = minimise(RECORD, "parcel_status")
for label, payload in (("full record", before), ("minimised", after)):
    sens = sorted(set(payload) & SENSITIVE_FIELDS)
    print(f"{label:<12} {len(payload):>2} fields, {len(sens)} sensitive")
    if sens:
        print("             " + ", ".join(sens[:4]))
        print("             " + ", ".join(sens[4:]))
print("minimised payload:", after)

# --- 3. A trace logged to the shared observability project ---------------
TRACE = {
    "prompt": f"Customer {RECORD['email']} ({RECORD['phone']}) asks: where "
              f"is my parcel?",
    "retrieved": [f"Card on file {RECORD['card_number']}",
                  f"SSN {RECORD['ssn']} verified 2026-01-04"],
    "reasoning": f"User is Alice, phone {RECORD['phone']}, card ends 1111; "
                 "order in transit, so answer with ETA only.",
    "answer": "Your parcel ORD-1042 is in transit and arrives Thursday.",
}

heading("3. The answer is clean. Is the trace?")
_, in_answer = scrub(TRACE["answer"])
clean, in_trace = scrub_trace(TRACE)
print(f"sensitive values in the answer:     {len(in_answer)}")
print(f"sensitive values in the full trace: {in_trace}")
print("trace after scrubbing, before it reaches the APM tool:")
print("  reasoning:", clip(clean["reasoning"], 58))
print("  retrieved:", clean["retrieved"])
print("note: the name 'Alice' survives. Patterns don't find names.")

# --- 4. A regex output filter meets encodings ----------------------------
LEAK = "Contact j.chen@kestrel-law.example or (555) 010-9921."
heading("4. The same leak, three spellings, one regex output filter")
for label, text in (
    ("plain", LEAK),
    ("base64", base64.b64encode(LEAK.encode()).decode()),
    ("hex", LEAK.encode().hex()),
):
    out, found = scrub(text)
    print(f"{label:<7} caught {len(found)}  ->  {clip(out, 56)}")

heading("Appendix: where the trace's sensitive values were")
for key, value in TRACE.items():
    texts = value if isinstance(value, list) else [value]
    labels = [f for v in texts for f in scrub(v)[1]]
    print(f"  {key:<10} {len(labels)}  {', '.join(labels) or '-'}")
