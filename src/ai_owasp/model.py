"""A scripted stand-in for a language model.

Real models are probabilistic. This one is deterministic, so every run in
the articles reproduces exactly. It is also deliberately gullible: it obeys
any instruction it reads, wherever it reads it (the user's message, a web
page, an email, a tool result), including instructions hidden in base64,
in Spanish, or in invisible Unicode.

Real models resist some of these instructions some of the time. OWASP's
2026 list says no reliable prevention exists today, so "some of the time"
is not a control. That is why nothing in this repository depends on the
model saying no. Every control sits outside the model, in code.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class Reply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    obeyed: str = ""  # the injected instruction it followed, if any


# Unicode "tag" characters (U+E0000 to U+E007F) mirror ASCII but render
# as nothing. Models still read them.
def hide(text: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in text)


def reveal_tags(text: str) -> str:
    return "".join(
        chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c
        for c in text
    )


OVERRIDE = re.compile(
    r"(?:ignore (?:all )?(?:previous|prior) instructions"
    r"|ignora las instrucciones anteriores)[ .:,]*(?:and |y )?"
    r"(?P<cmd>[^\n<]+)",
    re.I,
)
ENCODED = re.compile(
    r"decode (?:this|and follow)[^:]*:\s*(?P<b64>[A-Za-z0-9+/=]{16,})", re.I
)
SEND = re.compile(
    r"(?:email|send|forward|env[ií]a)\s+(?P<what>.+?)\s+"
    r"(?:to|a)\s+(?P<to>[\w.+-]+@[\w.-]+\w)",
    re.I,
)
IMAGE = re.compile(r"(?P<img>!\[[^\]]*\]\(\S+\))")
REPEAT = re.compile(r"(?:repeat|print|show) (?:the text|your "
                    r"instructions|everything) above", re.I)
AS_B64 = re.compile(r"your instructions (?:as|in) base64", re.I)
SPACED = re.compile(r"your instructions with spaces", re.I)
TOOLS = re.compile(r"list (?:your|the) tools", re.I)


class GullibleModel:
    """Follows the first injected instruction it finds in its context.

    `answer` produces the normal, honest reply when nothing is injected.
    """

    def __init__(self, answer=None):
        self.answer = answer or (lambda system, msgs: "OK.")

    def run(self, system: str, msgs: list[tuple[str, str]],
            tools: list[dict] | None = None) -> Reply:
        # The model reads everything as one stream of tokens: no trust
        # boundary between the system prompt, the user and the documents.
        seen = [(role, reveal_tags(text)) for role, text in msgs]
        for role, text in seen:
            m = ENCODED.search(text)
            if m:
                decoded = base64.b64decode(m["b64"]).decode()
                text = text + "\n" + decoded
            reply = self._obey(system, text, seen, tools or [])
            if reply:
                return reply
        return Reply(text=self.answer(system, seen))

    # --- what the model does once it has been "convinced" ---------------
    def _obey(self, system, text, seen, tools):
        m = OVERRIDE.search(text)
        if m:
            cmd = m["cmd"].strip()
            s = SEND.search(cmd)
            if s:
                body = private_context(seen)
                return Reply(
                    text="Done.",
                    tool_calls=[ToolCall("send_email",
                                         {"to": s["to"], "body": body})],
                    obeyed=cmd,
                )
            i = IMAGE.search(text)
            if i:
                data = private_context(seen).replace(" ", "+")[:60]
                img = i["img"].replace("{data}", data)
                summary = self.answer(system, seen)
                return Reply(text=f"{summary}\n\n{img}", obeyed=cmd)
        if REPEAT.search(text):
            return Reply(text=system, obeyed="repeat the text above")
        if AS_B64.search(text):
            return Reply(text=base64.b64encode(system.encode()).decode(),
                         obeyed="instructions as base64")
        if SPACED.search(text):
            return Reply(text=" ".join(system), obeyed="spaced letters")
        if TOOLS.search(text):
            return Reply(text=describe_tools(tools), obeyed="list tools")
        return None


def private_context(seen: list[tuple[str, str]]) -> str:
    """What a model would 'helpfully' put in an exfiltration payload: the
    private parts of the conversation (tool results and user turns)."""
    parts = [t for r, t in seen if r in ("tool", "user")]
    return " | ".join(p.split("\n")[0][:80] for p in parts)


def describe_tools(tools: list[dict]) -> str:
    lines = []
    for t in tools:
        lines.append(f"- {t['name']}: {t.get('description', '')}")
    return "\n".join(lines)
