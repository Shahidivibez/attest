/**
 * Poseidon commitment helper.
 *
 * The circuit commits to (score, dti, salt) with Poseidon. We must produce the
 * identical value in JS, so we use the same circomlib parameters via circomlibjs.
 */
const { buildPoseidon } = require("circomlibjs");

let _poseidon = null;

async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

/** Poseidon(score, dti, salt) as a decimal string (field element). */
async function inputCommit(score, dti, salt) {
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const h = poseidon([BigInt(score), BigInt(dti), BigInt(salt)]);
  return F.toString(h);
}

/** Fresh random field element, used as the commitment blinding salt. */
function randomSalt() {
  // Stay well inside the BN254 scalar field.
  const buf = require("crypto").randomBytes(31);
  return BigInt("0x" + buf.toString("hex")).toString();
}

module.exports = { getPoseidon, inputCommit, randomSalt };
