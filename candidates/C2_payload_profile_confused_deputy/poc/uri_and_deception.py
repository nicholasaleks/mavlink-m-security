import json, sys, copy
import jsonschema
root = sys.argv[1]
s = json.load(open(root + '/component_metadata/payloads.schema.json'))
V = jsonschema.validators.validator_for(s)(s)
P = jsonschema.validators.validator_for(s)({"$schema": s["$schema"], "definitions": s["definitions"], "$ref": "#/definitions/capabilityProfileDocument"})
cat = json.load(open(root + '/component_metadata/examples/payloads.example.json'))
uris = ["file:///etc/passwd.json", "file://C:/Users/op/AppData/Roaming/x.json", "http://169.254.169.254/latest/x.json",
        "https://10.0.0.5/admin/reboot.json?confirm=1", "mftp:///../../../../tmp/x.json", "mftp://..%2F..%2Fx.json",
        "mftp:///a/..%5C..%5C..%5CStartup%5Cevil.json", "gopher://127.0.0.1:6379/_x.json", "smb://host/share/x.json",
        "x.json", "https://user:pw@h/x.json"]
print("== capabilityProfileRef.definitionUri acceptance (schema only)")
for u in uris:
    c = copy.deepcopy(cat)
    for p in c['payloads']:
        for f in p['functions']:
            for r in f.get('capabilityProfiles', []): r['definitionUri'] = u
    print(f"  {'ACCEPT' if not list(V.iter_errors(c)) else 'reject'}  {u}")
print("== documentationUri acceptance")
for u in ["javascript:alert(1)", "file:///C:/Windows/System32/calc.exe", "\\\\attacker\\share\\doc.pdf", "data:text/html,<script>x</script>"]:
    c = copy.deepcopy(cat); c['payloads'][0]['documentationUri'] = u
    print(f"  {'ACCEPT' if not list(V.iter_errors(c)) else 'reject'}  {u}")
print("== label/description control characters & bidi")
c = copy.deepcopy(cat); c['payloads'][0]['functions'][0]['label'] = "Camera\u202e\u0000\u001b[2J" + "A"*100000
print("  ", 'ACCEPT' if not list(V.iter_errors(c)) else 'reject', "label with RLO, NUL, ESC, 100k chars")
# --- deceptive parachute profile: RELEASE presented as a disarm/"disable" ---
prof = json.load(open(root + '/component_metadata/examples/capability-profile-parachute.example.json'))
evil = copy.deepcopy(prof)
rel = [a for a in evil['actions'] if a['actionKey'] == 'release'][0]
rel['name'] = 'Disable auto-release (safe for handling)'
rel['description'] = 'Makes the parachute safe before recovery.'
rel['lifecycleEffect'] = 'disarm'          # classified as a disarm; for a non-PROTECTIVE function a disarm is a STOP
rel['idempotent'] = True                   # Client may resend under a new request_id after a lost outcome
# correlation still says param1 is PARACHUTE_RELEASE: the only place the command value is stated
print("== deceptive parachute profile schema errors:", len(list(P.iter_errors(evil))))
print("   action:", {k: rel[k] for k in ('name','lifecycleEffect','idempotent')}, "| correlation:", rel['bindings'][0]['correlation'][-40:])
# release as lifecycleEffect none -> no precondition, not 'special controlled', not covered by prevents:'activate'
evil2 = copy.deepcopy(prof); r2 = [a for a in evil2['actions'] if a['actionKey']=='release'][0]
r2['name'] = 'Run parachute self-check'; r2['lifecycleEffect'] = 'none'; r2['idempotent'] = True
print("== release-as-'none' profile schema errors:", len(list(P.iter_errors(evil2))))
json.dump(evil, open('out_deceptive_parachute_profile.json','w'), indent=2)
json.dump(evil2, open('out_deceptive_parachute_profile_none.json','w'), indent=2)
