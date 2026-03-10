"""
logic.py  –  Password strength analyzer with rockyou Bloom filter support.
"""

import re
import os

# ---------------------------------------------------------------
# Bloom filter loader (rockyou ~14M passwords)
# ---------------------------------------------------------------
_BLOOM = None
_BLOOM_PATH = os.path.join(os.path.dirname(__file__), "rockyou_bloom.bin")

def _load_bloom():
    global _BLOOM
    if _BLOOM is not None:
        return _BLOOM
    try:
        from pybloom_live import BloomFilter
        with open(_BLOOM_PATH, "rb") as f:
            _BLOOM = BloomFilter.fromfile(f)
        print(f"[✓] rockyou Bloom filter loaded")
    except FileNotFoundError:
        print(f"[!] rockyou_bloom.bin not found — using built-in list.")
        _BLOOM = None
    except ImportError:
        print("[!] pybloom-live not installed — using built-in list.")
        _BLOOM = None
    except Exception as e:
        print(f"[!] Bloom filter error: {e}")
        _BLOOM = None
    return _BLOOM

_load_bloom()

# ---------------------------------------------------------------
# Small built-in fallback list
# ---------------------------------------------------------------
_FALLBACK_COMMON = {
    "123456","password","123456789","12345678","12345","1234567",
    "1234567890","qwerty","abc123","111111","iloveyou","monkey",
    "dragon","master","sunshine","princess","welcome","shadow",
    "superman","michael","football","baseball","letmein","trustno1",
    "hello","charlie","donald","password1","1q2w3e4r","qwerty123",
    "p@ssword","p@ssw0rd","pa$$word","p@$$w0rd","pass123",
    "admin","login","test","user","root","guest","changeme",
    "passw0rd","password!","password123","abc1234","qazwsx",
    "1qaz2wsx","zaq12wsx","q1w2e3r4","1234qwer","123qwe",
}

def _in_rockyou(word: str) -> bool:
    return (word in _BLOOM) if _BLOOM is not None else (word in _FALLBACK_COMMON)

# ---------------------------------------------------------------
# Leet-speak normaliser
# ---------------------------------------------------------------
_LEET_MAP = str.maketrans({'@':'a','4':'a','3':'e','1':'i','!':'i',
                            '0':'o','5':'s','$':'s','7':'t','8':'b',
                            '+':'t','(':'c'})

def _normalize_leet(p: str) -> str:
    return p.lower().translate(_LEET_MAP)

# ---------------------------------------------------------------
# Attack checks
# ---------------------------------------------------------------
def _check_rockyou(password):
    lower = password.lower()
    if _in_rockyou(lower):
        src = "rockyou dataset (14M leaked passwords)" if _BLOOM else "common password list"
        return ("Dictionary / Credential Stuffing",
                f"⚠️ '{password}' was found in the {src}. "
                "Any attacker will crack this instantly with a dictionary attack.")
    return None

def _check_leet(password):
    norm = _normalize_leet(password)
    if norm != password.lower() and _in_rockyou(norm):
        return ("Hybrid Brute Force (Leet-speak)",
                f"⚠️ '{password}' is a leet-speak variant of a leaked password ('{norm}'). "
                "Hybrid attack tools test all substitutions automatically.")
    return None

def _check_keyboard_walk(password):
    walks = ["qwerty","qwertyui","asdfgh","zxcvbn","1qaz","2wsx",
             "3edc","1q2w3e","qazwsx","!qaz","@wsx","zaq1","xsw2"]
    lower = password.lower()
    for w in walks:
        if w in lower:
            return ("Simple Brute Force (Keyboard Walk)",
                    f"⚠️ Password contains keyboard-walk pattern '{w}'. "
                    "These are among the first patterns tried by brute-force scripts.")
    return None

def _check_sequential(password):
    for seq in ["0123456789","abcdefghijklmnopqrstuvwxyz"]:
        lower = password.lower()
        for n in range(4, 10):
            for i in range(len(seq)-n+1):
                chunk = seq[i:i+n]
                if chunk in lower:
                    return ("Simple Brute Force (Sequential Pattern)",
                            f"⚠️ Password contains sequential pattern '{chunk}'. "
                            "Automated tools enumerate these in seconds.")
    return None

def _check_repeated(password):
    if re.search(r'(.)\1{3,}', password):
        return ("Simple Brute Force (Repeated Characters)",
                "⚠️ Avoid 4+ consecutive identical characters — "
                "brute-force scripts prioritise these patterns.")
    return None

def _check_year(password):
    if re.search(r'(19|20)\d{2}[!@#$%^&*]?$', password):
        base = re.sub(r'(19|20)\d{2}[!@#$%^&*]?$', '', password)
        if len(base) >= 3:
            return ("Password Spraying / Hybrid Brute Force",
                    "⚠️ Appending a year (or year+symbol) is extremely common. "
                    "Password-spraying tools test patterns like 'Word2025!' against millions of accounts.")
    return None

def _check_personal(password):
    hits = []
    if re.match(r'^05\d[- ]?\d{7}$|^\d{10}$', password):
        hits.append(("Social Engineering",
                     "⚠️ Password looks like a phone number. "
                     "Attackers gather this via social engineering and try it first."))
    elif re.match(r'^\d{9}$', password):
        hits.append(("Targeted Attack (Personal ID)",
                     "⚠️ Password looks like an ID number — "
                     "a prime target for personalised attacks."))
    return hits

# ---------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------
def _pool(password):
    p = 0
    if any(c.islower() for c in password): p += 26
    if any(c.isupper() for c in password): p += 26
    if any(c.isdigit() for c in password): p += 10
    if any(not c.isalnum() for c in password): p += 32
    return p or 1

def _seconds(password):
    return (_pool(password) ** len(password)) / 1e10

def format_time(s):
    if s < 1: return "Instantly"
    if s > 100*31_536_000: return "Centuries (Unbreakable)"
    for lim, name in [(31_536_000,"years"),(86_400,"days"),
                      (3_600,"hours"),(60,"minutes"),(1,"seconds")]:
        if s >= lim:
            return f"{int(s/lim)} {name}"
    return "Instantly"

def _score(password, hits, s):
    n, p = len(password), _pool(password)
    if n < 6:                      sc = 1
    elif n >= 16 and p >= 68:      sc = 5
    elif n >= 12 and p >= 60:      sc = 4
    elif n >= 8  and p >= 36:      sc = 3
    else:                          sc = 2
    if hits:                       sc = min(sc, 2)
    if s < 60:                     sc = min(sc, 1)
    elif s < 86_400:               sc = min(sc, 2)
    return sc

# ---------------------------------------------------------------
# Public API
# ---------------------------------------------------------------
def analyze_password(password: str) -> dict:
    if not password:
        return {"score": 0, "human_time": "0 seconds", "warnings": []}

    singles = [_check_rockyou(password), _check_leet(password),
               _check_keyboard_walk(password), _check_sequential(password),
               _check_repeated(password), _check_year(password)]
    hits  = [c for c in singles if c]
    hits += _check_personal(password)

    s = _seconds(password)
    return {
        "score":          _score(password, hits, s),
        "seconds":        s,
        "human_time":     format_time(s),
        "warnings":       [f"[{lbl}] {msg}" for lbl, msg in hits],
        "rockyou_active": _BLOOM is not None,
    }