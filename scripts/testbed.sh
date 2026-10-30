#!/bin/sh
# WanHound acceptance test bench (Linux + Docker).
#
#   scripts/testbed.sh <path-to-linux-wanhound-binary>
#
# Starts a container with known port states (open / closed / filtered via
# iptables DROP and REJECT inside the container), audits it with
# `wanhound scan --lab`, and asserts every state, rule hit, the UDP
# results, and — after opening one more port — the diff and exit code 1.
# Needs python3 on the host for the assertions. Cleans up after itself.
set -eu
BIN=${1:?usage: testbed.sh <wanhound-binary>}
HERE=$(cd "$(dirname "$0")" && pwd)
NAME=wanhound-testbed
DATA=$(mktemp -d)
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$DATA"; }
trap cleanup EXIT

docker build -q -t wanhound-testbed "$HERE/testbed" >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --cap-add NET_ADMIN wanhound-testbed >/dev/null
ready=0
for _ in $(seq 1 60); do
  if docker logs "$NAME" 2>&1 | grep -q "bench ready"; then ready=1; break; fi
  sleep 0.5
done
if [ "$ready" != 1 ]; then
  echo "::error::test bench container did not start: $(docker logs "$NAME" 2>&1 | tail -3 | tr '\n' ' ')"
  docker logs "$NAME"
  exit 1
fi
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")
echo "bench at $IP"

PORTS=22,80,8080,8443,9000,10000
run() { "$BIN" scan --lab --offline --ipv4 "$IP" --label testbed --ports "$PORTS" --udp --data-dir "$DATA" --json; }

set +e; run > "$DATA/run1.json"; code1=$?; set -e
docker exec "$NAME" touch /tmp/open-10000; sleep 1
set +e; run > "$DATA/run2.json"; code2=$?; set -e

python3 - "$DATA/run1.json" "$DATA/run2.json" "$code1" "$code2" <<'PY'
import json, sys
r1, r2 = (json.load(open(p)) for p in sys.argv[1:3])
code1, code2 = int(sys.argv[3]), int(sys.argv[4])
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)
        print("::error::testbed: " + msg)  # GitHub annotation

t = r1["targets"][0]
openp = sorted(o["port"] for o in t["open"])
check(openp == [22, 80], f"open ports = {openp}, want [22, 80]")
check(t["counts"] == {"open": 2, "closed": 2, "filtered": 2}, f"counts = {t['counts']}, want 2 open / 2 closed (8443 RST, 10000) / 2 filtered (8080 DROP, 9000 ICMP admin-prohibited)")
ids = {f["rule_id"] for f in t["findings"]}
for want in ("KH-031", "KH-040", "KC-001", "KU-001"):
    check(want in ids, f"finding {want} present")
udp = {u["port"]: u["state"] for u in t["udp"]}
check(udp.get(53) == "open", f"udp 53 = {udp.get(53)}, want open")
check(udp.get(1900) == "open|filtered", f"udp 1900 = {udp.get(1900)}, want open|filtered (DROP)")
check(udp.get(123) == "closed", f"udp 123 = {udp.get(123)}, want closed (ICMP unreachable)")
check(t.get("changes") is None, "first run is the baseline")
check(code1 == 1, f"run 1 exit code = {code1}, want 1 (high-risk findings)")

c = r2["targets"][0]["changes"]
check(c is not None and c.get("opened") == [10000], f"run 2 diff opened = {c and c.get('opened')}, want [10000]")
check(code2 == 1, f"run 2 exit code = {code2}, want 1")
print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED")
sys.exit(1 if fails else 0)
PY
