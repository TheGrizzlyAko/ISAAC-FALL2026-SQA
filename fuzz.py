import os
import sys
import random

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "KubeSec"))

import scanner
import parser
import graphtaint

random.seed(1337)

METHOD_NAMES = [
    "scanner.isValidUserName",
    "scanner.isValidPasswordName",
    "scanner.isValidKey",
    "scanner.checkIfValidSecret",
    "parser.checkIfWeirdYAML",
    "parser.keyMiner",
    "parser.getValsFromKey",
    "parser.getValuesRecursively",
    "parser.getKeyRecursively",
    "graphtaint.constructHelmString",
]

selfref = {}
selfref["self"] = selfref


def deep(n):
    d = {}
    cur = d
    for _ in range(n):
        nxt = {}
        cur["k"] = nxt
        cur = nxt
    return d


NAUGHTY_STRINGS = [
    "",
    " ",
    "\x00",
    "A" * 100000,
    "\u00e9\u4f60\u597d\U0001f600",
    "%s%n",
    "../../etc/passwd",
    "' OR 1=1",
    "\n\r\t",
    "{{7*7}}",
]

WRONG_TYPES = [
    None,
    0,
    1,
    -1,
    3.14,
    True,
    False,
    [],
    [1, 2, 3],
    {},
    (),
    (1,),
    b"bytes",
    object(),
]

DICT_JUNK = [
    {},
    {"a": 1},
    {"a": {"b": {"c": 1}}},
    {1: "x", 2: "y"},
    {None: 1},
    {"a": [1, 2, {"b": 3}]},
    {"a": None, "b": True, "c": [{}, {"d": 1}]},
    deep(1500),
    selfref,
]

TUPLE_JUNK = [
    (),
    (1,),
    (1, 2),
    (1, 2, 3),
    ("a", "b", "c"),
    (None, None, None),
    ("a", "a", "x"),
    ("up", "low", 0),
    5,
    None,
    "abc",
    [1, 2, 3],
]

GENERAL_POOL = NAUGHTY_STRINGS + WRONG_TYPES + DICT_JUNK

findings = []
exercised = {}


def short(x):
    try:
        r = repr(x)
    except Exception:
        return "<unrepr-able %s>" % type(x).__name__
    except RecursionError:
        return "<unrepr-able %s>" % type(x).__name__
    if len(r) > 80:
        r = r[:77] + "..."
    return r


def record(name, inp, e):
    findings.append((name, short(inp), type(e).__name__, str(e)[:200]))


def fuzz(name, fn, primary, *rest):
    exercised[name] = exercised.get(name, 0) + 1
    try:
        fn(primary, *rest)
    except RecursionError as e:
        record(name, primary, e)
    except Exception as e:
        record(name, primary, e)


def fuzz_gen(name, fn, primary):
    exercised[name] = exercised.get(name, 0) + 1
    try:
        list(fn(primary))
    except RecursionError as e:
        record(name, primary, e)
    except Exception as e:
        record(name, primary, e)


for x in GENERAL_POOL:
    fuzz("scanner.isValidUserName", scanner.isValidUserName, x)
    fuzz("scanner.isValidPasswordName", scanner.isValidPasswordName, x)
    fuzz("scanner.isValidKey", scanner.isValidKey, x)
    fuzz("scanner.checkIfValidSecret", scanner.checkIfValidSecret, x)
    fuzz("parser.checkIfWeirdYAML", parser.checkIfWeirdYAML, x)
    fuzz("graphtaint.constructHelmString", graphtaint.constructHelmString, x)

for t in TUPLE_JUNK:
    fuzz("graphtaint.constructHelmString", graphtaint.constructHelmString, t)

for d in DICT_JUNK + WRONG_TYPES + NAUGHTY_STRINGS:
    fuzz("parser.keyMiner", parser.keyMiner, d, "needle")
    fuzz("parser.getValsFromKey", parser.getValsFromKey, d, "a", [])
    fuzz("parser.getKeyRecursively", parser.getKeyRecursively, d, [])
    fuzz_gen("parser.getValuesRecursively", parser.getValuesRecursively, d)


def rand_key():
    return random.choice(["a", "b", "c", 1, 2, None, "x"])


def rand_junk(depth=0):
    r = random.random()
    if depth > 3 or r < 0.3:
        return random.choice([
            random.randint(-1000, 1000),
            random.random(),
            "".join(random.choice("ab\x00 /%'") for _ in range(random.randint(0, 20))),
            None,
            True,
            (),
        ])
    if r < 0.65:
        return {rand_key(): rand_junk(depth + 1) for _ in range(random.randint(0, 4))}
    return [rand_junk(depth + 1) for _ in range(random.randint(0, 4))]


def rand_str():
    return "".join(random.choice("ab\x00 /%'\u00e9A") for _ in range(random.randint(0, 50)))


def rand_tuple():
    n = random.randint(0, 4)
    return tuple(random.choice([rand_str(), random.randint(0, 9), None]) for _ in range(n))


for _ in range(100):
    s = rand_str()
    v = rand_junk()
    fuzz("scanner.isValidUserName", scanner.isValidUserName, s)
    fuzz("scanner.isValidPasswordName", scanner.isValidPasswordName, s)
    fuzz("scanner.isValidKey", scanner.isValidKey, s)
    fuzz("scanner.checkIfValidSecret", scanner.checkIfValidSecret, s)
    fuzz("parser.checkIfWeirdYAML", parser.checkIfWeirdYAML, v)
    fuzz("graphtaint.constructHelmString", graphtaint.constructHelmString, rand_tuple())
    fuzz("parser.keyMiner", parser.keyMiner, v, "needle")
    fuzz("parser.getValsFromKey", parser.getValsFromKey, v, "a", [])
    fuzz("parser.getKeyRecursively", parser.getKeyRecursively, v, [])
    fuzz_gen("parser.getValuesRecursively", parser.getValuesRecursively, v)


def esc(s):
    return s.replace("\n", " ").replace("\r", " ")


lines = []
lines.append("FUZZING REPORT")
lines.append("")
lines.append("Summary: %d findings across %d methods fuzzed." % (len(findings), len(exercised)))
lines.append("")
lines.append("")
lines.append("METHODS EXERCISED")
lines.append("")
for m in METHOD_NAMES:
    hits = sum(1 for f in findings if f[0] == m)
    lines.append("%-32s calls=%-5d findings=%d" % (m, exercised.get(m, 0), hits))
lines.append("")
lines.append("")
lines.append("FINDINGS")
lines.append("")
for f in findings:
    lines.append("%s | %s | %s | %s" % (f[0], esc(f[1]), f[2], esc(f[3])))

with open(os.path.join(ROOT, "fuzz_report.txt"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")

print("fuzz: %d findings across %d methods fuzzed; report written to fuzz_report.txt" % (len(findings), len(exercised)))
