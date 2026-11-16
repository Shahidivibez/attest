#!/usr/bin/env bash
# Rebuild the circuit: compile → local ceremony → groth16 setup → export vk.
# Requires circom 2.1.x on PATH (https://docs.circom.io/getting-started/installation/)
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p circuits/build circuits/ptau

echo "[1/6] compile circuit"
circom circuits/policy.circom --r1cs --wasm --sym -l node_modules -o circuits/build

echo "[2/6] new power-12 ceremony (DEV ONLY — we hold the toxic waste)"
npx snarkjs powersoftau new bn128 12 circuits/ptau/pot12_0000.ptau

echo "[3/6] contribute"
npx snarkjs powersoftau contribute circuits/ptau/pot12_0000.ptau circuits/ptau/pot12_0001.ptau \
  --name="attest-dev" -e="attest $(date +%s)"

echo "[4/6] prepare phase 2"
npx snarkjs powersoftau prepare phase2 circuits/ptau/pot12_0001.ptau circuits/ptau/pot12_final.ptau

echo "[5/6] groth16 setup"
npx snarkjs groth16 setup circuits/build/policy.r1cs circuits/ptau/pot12_final.ptau circuits/build/policy_0000.zkey
npx snarkjs zkey contribute circuits/build/policy_0000.zkey circuits/build/policy_final.zkey \
  --name="attest-dev-1" -e="attest $(date +%s)"

echo "[6/6] export verification key"
npx snarkjs zkey export verificationkey circuits/build/policy_final.zkey circuits/build/verification_key.json

rm -f circuits/ptau/pot12_0000.ptau circuits/ptau/pot12_0001.ptau circuits/build/policy_0000.zkey

node -e "
const c=require('crypto'),fs=require('fs');
const vk=JSON.parse(fs.readFileSync('circuits/build/verification_key.json'));
console.log('');
console.log('nPublic:', vl=vk.nPublic);
console.log('vk sha256: 0x'+c.createHash('sha256').update(JSON.stringify(vk)).digest('hex'));
console.log('');
console.log('Register this verification key on Kurier, then set KURIER_API_KEY + ATTEST_VK_HASH.');
"
