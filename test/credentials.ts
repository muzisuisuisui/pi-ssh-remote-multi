/**
 * Offline regression test for the credential backend layer.
 *
 * Covers the parts that are easy to break by accident and impossible to notice
 * without a second machine: AES-GCM key-file round-trips and their endpoint
 * binding (AAD), backend tagging in the credential file, backend fallback when
 * the preferred keystore is unavailable, legacy untagged (DPAPI-era) values,
 * and best-effort keystore cleanup on `delete`/`clear`.
 *
 * Uses throwaway temp directories; never touches `~/.pi/agent`. Needs no SSH.
 */
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PersistentCredentialStore,
  createFileKeyCodec,
  resolveCredentialCodecs,
  type SecretCodec,
} from "../index.ts";

let failures = 0;
const check = (label: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail ? ` (${detail})` : ""}`);
  if (!ok) failures += 1;
};

const dir = mkdtempSync(join(tmpdir(), "pi-ssh-cred-"));
const keyPath = join(dir, "secret.key");
const mode = (path: string) => statSync(path).mode & 0o777;

const fakeDpapi: SecretCodec = {
  id: "dpapi",
  label: "Windows DPAPI",
  available: true,
  async protect(_endpointId, secret) { return Buffer.from(secret, "utf8").toString("base64"); },
  async unprotect(_endpointId, ciphertext) { return Buffer.from(ciphertext, "base64").toString("utf8"); },
};

const broken: SecretCodec = {
  id: "broken",
  label: "broken backend",
  available: true,
  async protect() { throw new Error("keyring locked"); },
  async unprotect() { throw new Error("keyring locked"); },
};

try {
  // ---- AES-256-GCM key file backend ----------------------------------------
  const fileCodec = createFileKeyCodec(keyPath);
  const ciphertext = await fileCodec.protect("10.0.0.21:22", "hunter2");
  check("file backend hides the plaintext", !ciphertext.includes("hunter2"), ciphertext.slice(0, 12));
  check("file backend round-trips", await fileCodec.unprotect("10.0.0.21:22", ciphertext) === "hunter2");
  check("created key file is 0600", mode(keyPath) === 0o600, mode(keyPath).toString(8));
  check("key file holds a 32-byte hex key", /^[0-9a-f]{64}$/.test(readFileSync(keyPath, "utf8").trim()));

  let wrongEndpointThrew = false;
  try { await fileCodec.unprotect("10.0.0.22:22", ciphertext); } catch { wrongEndpointThrew = true; }
  check("ciphertext is bound to its endpoint (AAD)", wrongEndpointThrew);

  let tamperedThrew = false;
  const tampered = Buffer.from(ciphertext, "base64");
  tampered[tampered.length - 1] ^= 0xff;
  try { await fileCodec.unprotect("10.0.0.21:22", tampered.toString("base64")); } catch { tamperedThrew = true; }
  check("tampered ciphertext is rejected by GCM", tamperedThrew);

  // ---- store: save, read, tag, permissions ---------------------------------
  const storePath = join(dir, "credentials.json");
  const store = new PersistentCredentialStore(storePath, [fileCodec]);
  check("store reports a usable backend", store.available && store.label === "encrypted key file", store.label);
  check("unsaved endpoint has no credential", !store.has("10.0.0.21:22"));

  const saved = await store.set("10.0.0.21:22", "hunter2");
  const stored = JSON.parse(readFileSync(storePath, "utf8")) as { version: number; passwords: Record<string, string> };
  check("set() persists through the file backend", saved.persisted && saved.backend === "encrypted key file", JSON.stringify(saved));
  check("credential file is tagged with the backend id", stored.passwords["10.0.0.21:22"]!.startsWith("file:"), stored.passwords["10.0.0.21:22"]!.slice(0, 8));
  check("credential file holds no plaintext", !readFileSync(storePath, "utf8").includes("hunter2"));
  check("credential file is 0600", mode(storePath) === 0o600, mode(storePath).toString(8));
  check("has() sees the saved endpoint", store.has("10.0.0.21:22"));
  check("backendFor() names the owning backend", store.backendFor("10.0.0.21:22") === "encrypted key file", String(store.backendFor("10.0.0.21:22")));
  check("get() decrypts the saved password", await store.get("10.0.0.21:22") === "hunter2");

  // The key survives in the key file, so a new process/store can still read it.
  const reopened = new PersistentCredentialStore(storePath, [createFileKeyCodec(keyPath)]);
  check("a fresh store reuses the existing key file", await reopened.get("10.0.0.21:22") === "hunter2");

  // ---- backend fallback when the preferred backend fails -------------------
  const chainPath = join(dir, "chain.json");
  const chained = new PersistentCredentialStore(chainPath, [broken, fileCodec]);
  const chainedResult = await chained.set("10.0.0.30:22", "fallback-pw");
  const chainedFile = JSON.parse(readFileSync(chainPath, "utf8")) as { passwords: Record<string, string> };
  check("failed primary backend falls through to the next one", chainedResult.persisted && chainedResult.backend === "encrypted key file", JSON.stringify(chainedResult));
  check("fallback write is tagged with the backend that succeeded", chainedFile.passwords["10.0.0.30:22"]!.startsWith("file:"));

  const deadStore = new PersistentCredentialStore(join(dir, "dead.json"), [broken]);
  const deadResult = await deadStore.set("10.0.0.30:22", "x");
  check("all-backends-failed reports the reason", !deadResult.persisted && /keyring locked/.test(deadResult.error ?? ""), deadResult.error ?? "none");

  // ---- legacy untagged values are Windows DPAPI ciphertext -----------------
  const legacyPath = join(dir, "legacy.json");
  writeFileSync(legacyPath, JSON.stringify({ version: 1, passwords: { "10.0.0.40:22": Buffer.from("legacy-pw").toString("base64") } }));
  const legacy = new PersistentCredentialStore(legacyPath, [fakeDpapi, fileCodec]);
  check("untagged legacy value is read as DPAPI", await legacy.get("10.0.0.40:22") === "legacy-pw");
  check("untagged legacy value reports the DPAPI backend", legacy.backendFor("10.0.0.40:22") === "Windows DPAPI", String(legacy.backendFor("10.0.0.40:22")));

  const legacyNoDpapi = new PersistentCredentialStore(legacyPath, [fileCodec]);
  check("DPAPI value stays unreadable without a DPAPI backend", await legacyNoDpapi.get("10.0.0.40:22") === undefined);
  check("unreadable entry is not reported as saved", !legacyNoDpapi.has("10.0.0.40:22"));

  // ---- corrupt payloads degrade to `undefined`, never throw ----------------
  const corruptPath = join(dir, "corrupt.json");
  writeFileSync(corruptPath, JSON.stringify({ version: 1, passwords: { "10.0.0.50:22": "file:AAAA" } }));
  const corrupt = new PersistentCredentialStore(corruptPath, [fileCodec]);
  let corruptThrew = false;
  let corruptValue: string | undefined = "sentinel";
  try { corruptValue = await corrupt.get("10.0.0.50:22"); } catch { corruptThrew = true; }
  check("corrupt credential yields undefined instead of throwing", !corruptThrew && corruptValue === undefined);

  // ---- keystore-backed secrets are removed outside the JSON file -----------
  const removals: string[] = [];
  const fakeKeystore: SecretCodec = {
    id: "fake-store",
    label: "Fake Keychain",
    available: true,
    async protect() { return ""; },
    async unprotect() { return "from-keychain"; },
    remove(endpointId) { removals.push(endpointId); },
  };
  const keystorePath = join(dir, "keystore.json");
  const keystore = new PersistentCredentialStore(keystorePath, [fakeKeystore]);
  await keystore.set("a:22", "x");
  const keystoreFile = JSON.parse(readFileSync(keystorePath, "utf8")) as { passwords: Record<string, string> };
  check("keystore backend leaves only a tag in the credential file", keystoreFile.passwords["a:22"] === "fake-store:", JSON.stringify(keystoreFile.passwords["a:22"]));
  check("keystore backend resolves the secret from the keychain", await keystore.get("a:22") === "from-keychain");

  await keystore.set("b:22", "y");
  check("delete() drops the tag", keystore.delete("a:22"));
  check("delete() on a missing entry is a no-op", !keystore.delete("a:22"));
  await new Promise((resolve) => setTimeout(resolve, 20));
  check("delete() also clears the keychain copy", removals.includes("a:22"), removals.join(","));

  check("clear() reports how many secrets it dropped", keystore.clear() === 1);
  await new Promise((resolve) => setTimeout(resolve, 20));
  check("clear() clears remaining keychain copies", removals.includes("b:22"), removals.join(","));
  check("clear() empties the credential file", Object.keys((JSON.parse(readFileSync(keystorePath, "utf8")) as { passwords: Record<string, string> }).passwords).length === 0);

  // ---- backend ordering ----------------------------------------------------
  const resolved = resolveCredentialCodecs();
  check("the portable file backend is always the last resort", resolved.at(-1)?.id === "file", resolved.map((codec) => codec.id).join(","));
  if (process.platform === "win32") check("Windows prefers DPAPI", resolved[0]?.id === "dpapi", resolved[0]?.id ?? "none");
  else check("DPAPI is not offered off Windows", !resolved.some((codec) => codec.id === "dpapi"), resolved.map((codec) => codec.id).join(","));
  check("every resolved backend is available", resolved.every((codec) => codec.available));
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
