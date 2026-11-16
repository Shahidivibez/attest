#!/usr/bin/env bash
# Isolated hardening tests: self-heal, rate limiting, tamper lock.
cd /home/user/attest || exit 1

cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; }
PIDS=""
trap cleanup EXIT

echo "=== A. self-heal after tamper ==="
rm -rf /tmp/healtest
PORT=3100 ATTEST_DATA_DIR=/tmp/healtest DEMO_HEAL_MS=6000 node src/server.js > /tmp/heal.log 2>&1 &
A=$!; PIDS="$PIDS $A"
sleep 13

curl -s -X POST localhost:3100/api/tamper -H 'content-type: application/json' -d '{"seq":1}' >/dev/null
curl -s localhost:3100/api/state | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log('  after tamper: chain='+(j.chain.ok?'INTACT':'BROKEN'),'tampered='+j.demo.tampered,'healsIn='+Math.ceil(j.demo.healInMs/1000)+'s')})"

echo "  waiting 8s..."
sleep 8
curl -s localhost:3100/api/state | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log('  after heal:   chain='+(j.chain.ok?'INTACT':'BROKEN'),'tampered='+j.demo.tampered,'entries='+j.stats.total)})"

echo
echo "=== B. rate limit (15 rapid tampers; 12/min allowed) ==="
codes=""
for i in $(seq 1 15); do
  codes="$codes $(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3100/api/tamper -H 'content-type: application/json' -d '{"seq":1}')"
done
echo "  $codes"
kill $A 2>/dev/null; PIDS=""

echo
echo "=== C. tamper lock ==="
rm -rf /tmp/locktest
PORT=3200 ATTEST_DATA_DIR=/tmp/locktest TAMPER_LOCKED=1 DEMO_TOKEN=s3cret node src/server.js > /tmp/lock.log 2>&1 &
B=$!; PIDS="$B"
sleep 13
printf "  no token:   %s\n" "$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3200/api/tamper -H 'content-type: application/json' -d '{"seq":1}')"
printf "  bad token:  %s\n" "$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3200/api/tamper -H 'content-type: application/json' -H 'x-demo-token: wrong' -d '{"seq":1}')"
printf "  good token: %s\n" "$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:3200/api/tamper -H 'content-type: application/json' -H 'x-demo-token: s3cret' -d '{"seq":1}')"

echo
echo "=== D. static assets ==="
printf "  snarkjs bundle: %s\n" "$(curl -s -o /dev/null -w '%{http_code} %{size_download}b %{content_type}' localhost:3200/vendor/snarkjs.min.js)"
printf "  verify page:    %s\n" "$(curl -s -o /dev/null -w '%{http_code}' localhost:3200/verify.html)"
printf "  proof api:      %s\n" "$(curl -s -o /dev/null -w '%{http_code}' localhost:3200/api/proof/0)"
printf "  health:         %s\n" "$(curl -s localhost:3200/health)"
