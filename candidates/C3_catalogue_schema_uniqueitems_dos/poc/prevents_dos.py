"""Catalogue-side variant: one inhibition whose `prevents` lists n distinct catalogueConstraintMember
objects (dicts are unsortable -> python-jsonschema uniqueItems is O(n^2)). No per-entry cap on
`prevents` exists in payload_metadata.md:109-131; only the 65536-value / 1 MiB / 2 MiB-string caps."""
import json, sys, time, copy
import jsonschema
schema = json.load(open(sys.argv[1])); base = json.load(open(sys.argv[2])); n = int(sys.argv[3])
cat = copy.deepcopy(base)
fn = cat['payloads'][0]['functions'][0]
fn['inhibitions'] = [{"inhibitId": 1, "label": "x", "description": "x",
                      "prevents": [{"instanceKey": "k", "actionKey": "a%d" % i} for i in range(n)]}]
raw = json.dumps(cat, separators=(',', ':')).encode()
def count(v):
    if isinstance(v, dict): return 1 + sum(count(x) for x in v.values())
    if isinstance(v, list): return 1 + sum(count(x) for x in v)
    return 1
print(f"n={n} bytes={len(raw)} (limit 1048576) values={count(cat)} (limit 65536)")
V = jsonschema.validators.validator_for(schema)(schema)
t = time.perf_counter(); errs = list(V.iter_errors(cat)); dt = time.perf_counter() - t
print(f"schema_errors={len(errs)} validate_time={dt:.2f}s")
