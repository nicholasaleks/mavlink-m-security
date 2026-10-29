"""Build a capability profile that is within every limit in payload_metadata.md:109-131
(256 KiB, 16384 values, depth<=16, 512 KiB strings, <=256 entries) and time jsonschema on it.
uniqueItems over unsortable (mixed-type) arrays is O(n^2) in python-jsonschema."""
import json, sys, time
import jsonschema
schema = json.load(open(sys.argv[1]))
n = int(sys.argv[2])
vals = []
for i in range(n):
    vals.append(i if i % 2 else "s%d" % i)   # mixed int/str -> sorted() raises TypeError -> quadratic path
prof = {
  "profileSchemaVersion": 1, "profileId": "com.example.dos", "profileVersion": 1,
  "name": "x", "description": "x",
  "properties": [{
    "propertyId": 1, "propertyKey": "p", "name": "p", "description": "p",
    "valueType": "enum", "allowedValues": vals, "readable": True, "writable": False,
    "bindings": [{"bindingId": 1, "bindingKey": "b", "service": "payload-operation", "interfaceVersion": "1",
                  "role": "read", "requestMessage": "PAYLOAD_OPERATION_REQUEST", "responseMessage": "PAYLOAD_OPERATION_STATUS",
                  "correlation": "x"}]}]}
raw = json.dumps(prof, separators=(',', ':')).encode()
def count(v):
    if isinstance(v, dict): return 1 + sum(count(x) for x in v.values())
    if isinstance(v, list): return 1 + sum(count(x) for x in v)
    return 1
def strbytes(v):
    if isinstance(v, dict): return sum(len(k.encode()) + strbytes(x) for k, x in v.items())
    if isinstance(v, list): return sum(strbytes(x) for x in v)
    return len(v.encode()) if isinstance(v, str) else 0
print(f"n={n} bytes={len(raw)} (limit 262144) values={count(prof)} (limit 16384) strings={strbytes(prof)} (limit 524288)")
ps = {"$schema": schema["$schema"], "definitions": schema["definitions"], "$ref": "#/definitions/capabilityProfileDocument"}
V = jsonschema.validators.validator_for(schema)(ps)
t = time.perf_counter(); errs = list(V.iter_errors(prof)); dt = time.perf_counter() - t
print(f"valid={not errs} validate_time={dt:.2f}s")
