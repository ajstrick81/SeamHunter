"""Regional / geo-configuration discovery — reconstructed by data flow, not by method names.

Earlier revisions matched getters/setters/consumers by name, which collapses under real R8/DexGuard
obfuscation (the override getter is `u()`, the setter `e0()`, the consumer a renamed `isCountry`).
This version anchors on the override *key string* and the *SharedPreferences / field edges* around it:

  key string  →  the method(s) that reference it
              →  getter  (reads a field or calls SharedPreferences.get* with the key)
              →  setter  (writes that field or calls SharedPreferences.put* ; often upper-cases first)
              →  downstream consumers  (callers of the getter / readers of the field — by edge)
              →  normalization  (a consumer, or its caller, that compares region-code values)

Nothing is reported as a getter/setter/consumer unless it is connected to the same key string or
field by a real edge. Client-side country/region overrides are kept distinct from experiment
segmentation (`mockRegion`) and consent geolocation (OneTrust), and every record carries the
limitation that these are client-side testing/config controls — not a proven geoblock bypass.
"""
from __future__ import annotations

import os
import re

KIND_COUNTRY = "country/region override"
KIND_EXPERIMENT = "experiment region"
KIND_CONSENT = "consent geolocation"

_OVERRIDE_RE = re.compile(r"(?i)(sudo)?country[_]?override|region[_]?override|country[_]?code[_]?override")
_MOCK_RE = re.compile(r"(?i)mock[_]?region")
_CONSENT_RE = re.compile(r"(?i)onetrust|otpublishers|consent.*(country|region|geo)|geo.*consent")
_PREFS_FILE = re.compile(r"(?i)(debug).*pref|pref.*(debug)|debug_prefs")
_REGION_VALUE = re.compile(r"^(US|GB|UK|CA|AU|MX|OTHER|DE|FR|IN|BR|JP|US-.*)$")
_DEFAULTISH = re.compile(r"^(Default|default|none|NONE|)$")
_FRAMEWORK = ("Ljava/", "Landroid/", "Lkotlin/", "Landroidx/")


def _prefs(bundle):
    out = []
    try:
        for split, zi in bundle.iter_files():
            n = zi.filename
            if not n.lower().endswith(".xml") or not _PREFS_FILE.search(os.path.basename(n)):
                continue
            if zi.file_size > 200_000:
                continue
            try:
                text = split.read(n).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
            keys = re.findall(r'<(?:string|boolean|int|long|float)\s+name="([^"]+)"(?:\s+value="([^"]*)")?\s*>?([^<]*)', text)
            out.append({"file": n, "keys": [{"key": k, "default": (val or body).strip()} for k, val, body in keys]})
    except Exception:  # noqa: BLE001
        pass
    return out


_KPROP_ARRAY_T = "[Lkotlin/reflect/KProperty"      # KProperty[] metadata array, by TYPE (name may be renamed)

# smali instruction shapes (one per line, after strip) for the slot bridge
_RE_CONST = re.compile(r"^const(?:/4|/16|/high16|/jumbo|-wide(?:/\w+)?)?\s+(\w+),\s+(-?0x[0-9a-fA-F]+|-?\d+)")
_RE_CONSTSTR = re.compile(r'^const-string(?:/jumbo)?\s+(\w+),\s+"(.*)"$')
_RE_NEWARRAY = re.compile(r"^new-array\s+(\w+),\s+\w+,\s+(\S+)")
_RE_SGET = re.compile(r"^sget-object\s+(\w+),\s+(\S+)")
_RE_IGET = re.compile(r"^iget-object\s+(\w+),\s+\w+,\s+(\S+)")
_RE_SPUT = re.compile(r"^sput-object\s+(\w+),\s+(\S+)")
_RE_IPUT = re.compile(r"^iput-object\s+(\w+),\s+\w+,\s+(\S+)")
_RE_AGET = re.compile(r"^aget-object\s+(\w+),\s+(\w+),\s+(\w+)")
_RE_APUT = re.compile(r"^aput-object\s+(\w+),\s+(\w+),\s+(\w+)")
_RE_INVOKE = re.compile(r"^invoke-\w+(?:/range)?\s+\{([^}]*)\},\s+(\S+)")
_RE_NEWINST = re.compile(r"^new-instance\s+(\w+),")
_RE_MOVERES = re.compile(r"^move-result-object\s+(\w+)")
_RE_MOVEOBJ = re.compile(r"^move-object(?:/from16)?\s+(\w+),\s+(\w+)")


def _field_name(fref):
    return fref.split("->", 1)[1].split(":", 1)[0] if "->" in fref else fref


def _field_type(fref):
    return fref.rsplit(":", 1)[-1] if ":" in fref else ""


def _is_kprop_array_field(fref):
    return _field_type(fref).startswith(_KPROP_ARRAY_T)


def _delegate_field(fref):
    """A non-metadata, object-typed instance field — the delegate instance, not the KProperty[] array."""
    return (not fref.startswith(_FRAMEWORK) and not _field_name(fref).startswith("$")
            and not _is_kprop_array_field(fref) and _field_type(fref).startswith("L"))


def _nonmeta_fields(idx, mid):
    out = []
    for fr, w in idx.field_access(mid):
        if fr.startswith(_FRAMEWORK) or _field_name(fr).startswith("$") or _is_kprop_array_field(fr):
            continue
        out.append((fr, w))
    return out


def _clinit_rows(idx, cls):
    return idx.q(idx.METHOD_SQL + "WHERE c.name=? AND m.name IN ('<clinit>','<init>')", cls)


def _is_propref_type(idx, cls):
    """True if a (possibly renamed) class derives from Kotlin's property-reference hierarchy — a
    name-independent corroboration for the structural ctor shape."""
    row = idx.class_row(cls)
    if not row:
        return False
    chain = (row["super"] or "") + " " + (row["interfaces"] or "")
    return "PropertyReference" in chain or "kotlin/reflect/KProperty" in chain


def _delegate_default(idx, cls, field_ref, key_rx):
    """The default for THIS delegate: the string that flows into the delegate factory whose result is
    written to `field_ref` — not the first default-ish string in <clinit> (real <clinit> initializes
    many delegates and may hold "" before "Default")."""
    for row in _clinit_rows(idx, cls):
        try:
            lines = idx.smali(row).splitlines()
        except Exception:  # noqa: BLE001
            continue
        reg_str, reg_val = {}, {}       # reg -> const string ; reg(object) -> carried default string
        pending = None                   # default string carried by the last invoke's result
        for raw in lines:
            t = raw.strip()
            m = _RE_CONSTSTR.match(t)
            if m:
                reg_str[m.group(1)] = m.group(2); reg_val.pop(m.group(1), None)
                continue
            m = _RE_NEWINST.match(t)
            if m:
                reg_val.pop(m.group(1), None); reg_str.pop(m.group(1), None)
                continue
            m = _RE_INVOKE.match(t)
            if m:
                args = [a.strip() for a in m.group(1).split(",") if a.strip()]
                strs = [reg_str[a] for a in args if a in reg_str and not key_rx.search(reg_str[a])]
                chosen = next((s for s in strs if _DEFAULTISH.match(s) or _REGION_VALUE.match(s)), strs[0] if strs else None)
                pending = chosen
                if "-><init>(" in m.group(2) and args and chosen is not None:
                    reg_val[args[0]] = chosen          # delegate ctor: receiver carries its seed value
                continue
            m = _RE_MOVERES.match(t)
            if m:
                if pending is not None:
                    reg_val[m.group(1)] = pending
                continue
            m = _RE_MOVEOBJ.match(t)
            if m:
                if m.group(2) in reg_val:
                    reg_val[m.group(1)] = reg_val[m.group(2)]
                continue
            m = _RE_IPUT.match(t) or _RE_SPUT.match(t)
            if m:
                src = m.group(1)
                fld = m.group(m.lastindex)
                if fld == field_ref and (src in reg_val or src in reg_str):
                    return reg_val.get(src, reg_str.get(src))
    return None


def _clinit_key_slots(idx, cls, key_rx):
    """Slots in the KProperty[] array that the key's property-reference is stored into.

    Bridges unrenamed Kotlin metadata (the property *name* `sudoCountryOverride`, kept for reflection)
    to the renamed executable accessors via the actual array slot — independent of the getter name in
    the signature string (which R8 does NOT rename to match the method). Register taint: a register
    holding a property-reference built from the key name is followed through factory calls / moves
    until its `aput-object` into the KProperty[] array fixes the slot index.
    """
    slots = set()
    for row in idx.q(idx.METHOD_SQL + "WHERE c.name=? AND m.name='<clinit>'", cls):
        try:
            lines = idx.smali(row).splitlines()
        except Exception:  # noqa: BLE001
            continue
        arr_regs, const_i, str_reg, taint = set(), {}, {}, set()
        last_invoke_tainted = False
        for raw in lines:
            t = raw.strip()
            m = _RE_CONSTSTR.match(t)
            if m:
                str_reg[m.group(1)] = m.group(2)
                taint.discard(m.group(1)); const_i.pop(m.group(1), None)
                continue
            m = _RE_CONST.match(t)
            if m:
                const_i[m.group(1)] = int(m.group(2), 0)
                taint.discard(m.group(1)); str_reg.pop(m.group(1), None)
                continue
            m = _RE_NEWARRAY.match(t)
            if m:
                (arr_regs.add if "Lkotlin/reflect/KProperty" in m.group(2) else arr_regs.discard)(m.group(1))
                taint.discard(m.group(1))
                continue
            m = _RE_NEWINST.match(t)
            if m:                              # a fresh object clears any prior taint on this register
                taint.discard(m.group(1)); str_reg.pop(m.group(1), None); const_i.pop(m.group(1), None)
                continue
            m = _RE_SGET.match(t)
            if m:
                (arr_regs.add if _is_kprop_array_field(m.group(2)) else arr_regs.discard)(m.group(1))
                taint.discard(m.group(1))
                continue
            m = _RE_INVOKE.match(t)
            if m:
                target = m.group(2)
                args = [a.strip() for a in m.group(1).split(",") if a.strip()]
                namehit = any(a in str_reg and key_rx.search(str_reg[a]) for a in args)
                # Recognize the property-reference constructor STRUCTURALLY, not by class name — R8
                # renames `MutablePropertyReference1Impl` to e.g. `Lkotlin/jvm/internal/x;`. The shape is
                # a ctor taking (owner, name, getter-signature, ...): >=2 String params, one of which is
                # the property name. (Optionally the owner derives from Kotlin's property-ref hierarchy.)
                is_ctor = "-><init>(" in target
                pr_shape = target.count("Ljava/lang/String;") >= 2
                if is_ctor and namehit and args and (pr_shape or _is_propref_type(idx, target.split("->")[0])):
                    taint.add(args[0])            # receiver becomes the key property-reference
                last_invoke_tainted = namehit or any(a in taint for a in args)
                continue
            m = _RE_MOVERES.match(t)
            if m:
                (taint.add if last_invoke_tainted else taint.discard)(m.group(1))
                continue
            m = _RE_MOVEOBJ.match(t)
            if m:
                (taint.add if m.group(2) in taint else taint.discard)(m.group(1))
                continue
            m = _RE_APUT.match(t)
            if m:
                obj, arr, idxr = m.groups()
                if obj in taint and arr in arr_regs and idxr in const_i:
                    slots.add(const_i[idxr])
                continue
    return slots


def _accessor_slots_fields(idx, mid):
    """(slots the method reads from a KProperty[] array, delegate fields it reads)."""
    try:
        lines = idx.smali(idx.method(mid)).splitlines()
    except Exception:  # noqa: BLE001
        return set(), set()
    arr_regs, const_i, slots, del_fields = set(), {}, set(), set()
    for raw in lines:
        t = raw.strip()
        m = _RE_CONST.match(t)
        if m:
            const_i[m.group(1)] = int(m.group(2), 0)
            arr_regs.discard(m.group(1))
            continue
        m = _RE_NEWARRAY.match(t)
        if m:
            (arr_regs.add if "Lkotlin/reflect/KProperty" in m.group(2) else arr_regs.discard)(m.group(1))
            continue
        for rx in (_RE_SGET, _RE_IGET):
            m = rx.match(t)
            if m:
                dst, fld = m.group(1), m.group(2)
                if _is_kprop_array_field(fld):
                    arr_regs.add(dst)
                else:
                    arr_regs.discard(dst)
                    if _delegate_field(fld):
                        del_fields.add(fld)
                break
        m = _RE_AGET.match(t)
        if m:
            dst, arr, idxr = m.groups()
            if arr in arr_regs and idxr in const_i:
                slots.add(const_i[idxr])
            arr_regs.discard(dst)
    return slots, del_fields


def _reconstruct(idx, key_rx, kind, limitation, prefs_keys):
    # 1. the override key string(s)
    keys = sorted({v for (v,) in idx.q("SELECT value FROM strings WHERE length(value) < 120") if key_rx.search(v)})
    pref_key = next((k for k in prefs_keys if key_rx.search(k)), None)
    if not keys and not pref_key:
        return None

    recs = {}
    for k in keys:
        for r in idx.string_users(k, exact=True, limit=60):
            recs[r["id"]] = r
    owner_classes = {r["cls"] for r in recs.values()}

    getters, setters, fields = [], [], set()
    default_val = None

    def _note_default(mid):
        nonlocal default_val
        if default_val is None:
            for s in idx.strings_of(mid):
                if not key_rx.search(s) and (_DEFAULTISH.match(s) or _REGION_VALUE.match(s)):
                    default_val = s
                    return

    # ---- (A) direct pattern: a key-referencing method that uses SharedPreferences or its own field.
    # A country/region override holds a String, so the getter must return String and the setter take one.
    for mid, r in recs.items():
        if r["name"] in ("<clinit>", "<init>"):
            _note_default(mid)
            continue
        calls = idx.calls_of(mid)
        facc = _nonmeta_fields(idx, mid)
        reads = [fr for fr, w in facc if not w]
        writes = [fr for fr, w in facc if w]
        has_get = any("SharedPreferences;->get" in c or "->getString(" in c for c in calls)
        has_put = any("Editor;->put" in c or "Editor;->apply" in c or "Editor;->commit" in c for c in calls)
        upper = any("->toUpperCase(" in c for c in calls)
        if r["ret"] == "Ljava/lang/String;" and (has_get or reads):
            getters.append({"sig": idx.sig(r), "id": mid, "via": "SharedPreferences.get" if has_get else "field read"})
            fields.update(reads)
            _note_default(mid)
        elif r["ret"] == "V" and "Ljava/lang/String;" in r["params"] and (has_put or writes):
            via = "SharedPreferences.put + toUpperCase" if (has_put and upper) else \
                  "SharedPreferences.put" if has_put else "field write"
            setters.append({"sig": idx.sig(r), "id": mid, "via": via})
            fields.update(reads + writes)

    # ---- (B) Kotlin delegated-property pattern, bridged by the KProperty array SLOT (not by name).
    # <clinit> stores the key's property-reference at a fixed slot; the real accessors (whatever R8
    # renamed them to) load that same slot and a delegate field. Pair the String getter and the
    # void(String) setter that read the same key slot + delegate field.
    delegated_fields = set()
    for cls in owner_classes:
        key_slots = _clinit_key_slots(idx, cls, key_rx)
        if not key_slots:
            continue
        getter_fields = set()
        for r in idx.q(idx.METHOD_SQL + "WHERE c.name=?", cls):
            if r["name"] in ("<clinit>", "<init>"):
                continue
            slots, dfields = _accessor_slots_fields(idx, r["id"])
            if not (slots & key_slots) or not dfields:
                continue
            if r["ret"] == "Ljava/lang/String;":
                getters.append({"sig": idx.sig(r), "id": r["id"],
                                "via": f"Kotlin delegated property (KProperty slot {min(slots & key_slots)})"})
                fields.update(dfields)
                getter_fields |= dfields
            elif r["ret"] == "V" and "Ljava/lang/String;" in r["params"]:
                setters.append({"sig": idx.sig(r), "id": r["id"],
                                "via": f"Kotlin delegated property (KProperty slot {min(slots & key_slots)})"})
                fields.update(dfields)
        # keep setters that share the getter's delegate field when we found a getter
        if getter_fields:
            setters = [s for s in setters if _accessor_slots_fields(idx, s["id"])[1] & getter_fields] or setters
            delegated_fields |= getter_fields

    # A delegated owner often initializes dozens of properties in one constructor. Resolve the
    # default from the factory/constructor result written to the selected delegate field; never use
    # the first default-looking string in the whole method (which is commonly an unrelated "").
    for fr in sorted(delegated_fields):
        owner = fr.split("->", 1)[0]
        field_default = _delegate_default(idx, owner, fr, key_rx)
        if field_default is not None:
            default_val = field_default
            break
    if default_val is None and pref_key:
        default_val = prefs_keys.get(pref_key)

    def _dedup(lst):
        seen, out = set(), []
        for x in lst:
            if x["id"] not in seen:
                seen.add(x["id"])
                out.append(x)
        return out

    getters, setters = _dedup(getters), _dedup(setters)

    # 3. downstream consumers, strictly by edge: callers of a getter, or readers of the override field —
    # excluding the getter/setter methods themselves (they read the delegate field too).
    consumers = {}
    getter_ids = {g["id"] for g in getters}
    accessor_ids = getter_ids | {s["id"] for s in setters} | set(recs)
    for g in getters:
        for c in idx.callers(g["sig"], exact=True, limit=25):
            if c["id"] not in accessor_ids:
                consumers[c["id"]] = idx.sig(c)
    for fr in fields:
        for u in idx.field_users(fr, write=False, exact=True, limit=25):
            if u["id"] not in accessor_ids:
                consumers[u["id"]] = idx.sig(u)

    # 4. normalization: a consumer (or a caller of one) that compares region-code values — connected,
    # never a globally-matched name. Follow one extra hop up so a renamed isCountry() is caught.
    def _refs_region(mid):
        return any(_REGION_VALUE.match(s) for s in idx.strings_of(mid))

    normalization = []
    country_context = re.compile(r"(?i)country|region|locale")
    comparison_calls = ("Ljava/lang/String;->equals(",
                        "Lkotlin/jvm/internal/r;->c(",
                        "Lkotlin/jvm/internal/Intrinsics;->areEqual(")
    for cid, csig in list(consumers.items()):
        if _refs_region(cid):
            normalization.append(csig)
        for up in idx.callers(csig, exact=True, limit=15):
            up_strings = idx.strings_of(up["id"])
            calls = idx.calls_of(up["id"])
            compares_country = (any(country_context.search(s) for s in up_strings)
                                and any(any(marker in call for marker in comparison_calls) for call in calls))
            if (up["id"] not in recs and up["id"] not in getter_ids
                    and (_refs_region(up["id"]) or compares_country)):
                consumers.setdefault(up["id"], idx.sig(up))
                normalization.append(idx.sig(up))

    # 5. confidence from how much of the chain connected (not from name hits)
    chain = bool(getters) and (bool(consumers) or bool(fields))
    conf = "high" if (chain and (setters or pref_key)) else "medium" if (getters or setters) else "low"
    if not (getters or setters or consumers):
        conf = "low"
    return {
        "kind": kind,
        "key_strings": keys[:5],
        "preference": pref_key,
        "default": default_val,
        "fields": sorted(fields)[:4],
        "getters": [g["sig"] + f"  [{g['via']}]" for g in getters][:4],
        "setters": [s["sig"] + f"  [{s['via']}]" for s in setters][:4],
        "downstream_consumers": sorted(set(consumers.values()))[:6],
        "normalization": sorted(set(normalization))[:4],
        "confidence": conf,
        "limitation": limitation,
        "reconstructed_by": "data flow (key string + field/SharedPreferences edges), not method names",
    }


def _consent(idx):
    methods = [idx.sig(r) for r in idx.q(
        "SELECT m.id, c.name AS cls, m.name, m.params, m.ret FROM methods m JOIN classes c ON c.id=m.class "
        "WHERE c.is_app=1") if _CONSENT_RE.search(r["name"] or "")]
    strings = [v for (v,) in idx.q("SELECT value FROM strings WHERE length(value) < 120") if _CONSENT_RE.search(v)]
    # a CMP (OneTrust) class is a real vendor name, legitimately detected by package, not obfuscated app code
    cmp_cls = [r[0] for r in idx.q("SELECT name FROM classes WHERE name LIKE '%onetrust%' OR name LIKE '%OTPublishers%' LIMIT 4")]
    if not (methods or strings or cmp_cls):
        return None
    return {
        "kind": KIND_CONSENT, "key_strings": strings[:4], "preference": None, "default": None,
        "fields": [], "getters": methods[:4], "setters": [], "downstream_consumers": [],
        "normalization": [], "cmp_classes": cmp_cls, "confidence": "medium" if (methods or cmp_cls) else "low",
        "reconstructed_by": "vendor CMP class / consent-geo references",
        "limitation": "Consent-region processing (CMP / OneTrust). Governs privacy/consent handling, "
                      "NOT content availability — do not present it as a geoblock or licensing control.",
    }


def detect(idx, bundle=None) -> dict:
    prefs = _prefs(bundle) if bundle is not None else []
    prefs_keys = {k["key"]: k["default"] for p in prefs for k in p["keys"]}
    overrides = []
    country = _reconstruct(idx, _OVERRIDE_RE, KIND_COUNTRY, prefs_keys=prefs_keys, limitation=(
        "Client-side testing/configuration override only — it changes the country code the app's "
        "locale/config checks read. It is NOT proof of a licensing or geoblock bypass: server and CDN "
        "authorization may still enforce on the public IP or the account."))
    if country:
        overrides.append(country)
    experiment = _reconstruct(idx, _MOCK_RE, KIND_EXPERIMENT, prefs_keys=prefs_keys, limitation=(
        "Affects experiment segmentation, not ordinary locale/config checks — distinct from the country "
        "override; it does not change content-availability enforcement."))
    if experiment:
        overrides.append(experiment)
    consent = _consent(idx)
    if consent:
        overrides.append(consent)

    present = bool(overrides)
    summary = None
    if present:
        kinds = ", ".join(sorted({o["kind"] for o in overrides}))
        summary = (f"Regional/configuration controls found ({kinds}), reconstructed by data flow. "
                   "Country/region overrides are client-side; consent geolocation and experiment region "
                   "are tracked separately and are not content-availability controls.")
    return {
        "present": present,
        "overrides": overrides,
        "prefs_files": prefs,
        "summary": summary,
        "limitation": "Client-side configuration/testing controls. Server/CDN authorization may still rely "
                      "on public IP or account state; do not read these as a proven licensing/geoblock bypass.",
    }
