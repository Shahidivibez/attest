/**
 * ATTEST · store
 *
 * Persistence for the demo. Four files, with distinct trust roles:
 *
 *   decisions.json  the live record — what the app currently claims
 *   pristine.json   last known-good snapshot, used to self-heal after a demo
 *   anchors.json    the roots we published. Deliberately NOT updated by the
 *                   tamper path, so an edit cannot rewrite what we claimed.
 *   meta.json       operational state (when a tamper demo last ran)
 *
 * Splitting the anchor record out of the decision file is the whole trick: an
 * attacker with write access to decisions.json cannot reach anchors.json
 * through the same code path, so the published root survives the edit.
 */
const fs = require("fs");
const path = require("path");

const DATA_DIR = process.env.ATTEST_DATA_DIR || path.join(__dirname, "..", "data");
const FILES = {
  decisions: path.join(DATA_DIR, "decisions.json"),
  pristine: path.join(DATA_DIR, "pristine.json"),
  anchors: path.join(DATA_DIR, "anchors.json"),
  meta: path.join(DATA_DIR, "meta.json"),
};

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJson(file, fallback) {
  ensure();
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  ensure();
  // Write-then-rename so a crash mid-write cannot leave a truncated record —
  // which would look exactly like tampering, and we'd rather not frame
  // ourselves.
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}

/* ---- live record ---------------------------------------------------- */

const loadEntries = () => readJson(FILES.decisions, []);
const saveEntries = (e) => writeJson(FILES.decisions, e);

/* ---- pristine snapshot (self-healing) -------------------------------- */

const loadPristine = () => readJson(FILES.pristine, null);
const savePristine = (v) => writeJson(FILES.pristine, v);

/* ---- published anchors ----------------------------------------------- */

const loadAnchors = () => readJson(FILES.anchors, []);
const saveAnchors = (a) => writeJson(FILES.anchors, a);

function latestAnchor() {
  const a = loadAnchors();
  return a.length ? a[a.length - 1] : null;
}

/* ---- operational meta ------------------------------------------------ */

const loadMeta = () => readJson(FILES.meta, {});
const saveMeta = (m) => writeJson(FILES.meta, m);
const patchMeta = (p) => {
  const m = { ...loadMeta(), ...p };
  saveMeta(m);
  return m;
};

module.exports = {
  DATA_DIR,
  FILES,
  loadEntries, saveEntries,
  loadPristine, savePristine,
  loadAnchors, saveAnchors, latestAnchor,
  loadMeta, saveMeta, patchMeta,
};
