/**
 * Pi SSH Remote extension.
 *
 * Provides persistent SSH workspaces for Pi by routing file and shell tools to
 * a verified remote host. It manages endpoint configuration, protected
 * credentials, remote working directories, reconnection, and TCP forwarding.
 */

import { Client, createAgent, type ClientChannel, type ConnectConfig, type SFTPWrapper, type Stats } from "ssh2";
import { spawn } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  accessSync,
  chmodSync,
  constants as fsConstants,
  promises as fsPromises,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute as isLocalAbsolute,
  join,
  posix as pathPosix,
  relative,
  resolve as resolveLocal,
  sep,
} from "node:path";
import { pipeline } from "node:stream/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  createBashTool,
  createEditTool,
  createReadTool,
  createWriteTool,
  formatSize,
  getAgentDir,
  keyHint,
  truncateTail,
  type BashOperations,
  type EditOperations,
  type ReadOperations,
  type WriteOperations,
} from "@earendil-works/pi-coding-agent";
import { CURSOR_MARKER, Key, Text, matchesKey, truncateToWidth, type Component, type Focusable } from "@earendil-works/pi-tui";

interface ParsedSsh {
  host: string;
  port: number;
  username: string;
  label: string;
  command: string;
}

interface RemoteState extends ParsedSsh {
  client: Client;
  cwd: string;
  home: string;
}

interface CredentialCache {
  passwords: Map<string, string>;
  resume?: { command: string; cwd: string };
}

export interface SecretCodec {
  /** Stable tag persisted next to the ciphertext, e.g. `dpapi` or `file`. */
  readonly id: string;
  /** Short human-readable backend name for UI messages. */
  readonly label: string;
  /** Whether this backend can be used in the current environment. */
  readonly available: boolean;
  /**
   * Encrypt/hand the secret to the backend. `endpointId` is used both as AES-GCM
   * associated data (file backend) and as the keychain account name.
   */
  protect(endpointId: string, secret: string): Promise<string>;
  unprotect(endpointId: string, ciphertext: string): Promise<string>;
  /** Best-effort removal of an out-of-file copy (OS keychains own the secret). */
  remove?(endpointId: string): Promise<void> | void;
}

interface PersistentCredentialFile {
  version: 1;
  passwords: Record<string, string>;
}

interface RemoteEndpointConfig {
  sshCommand?: string;
  remoteCwd?: string;
  forwards?: string[];
  note?: string;
  /** Default remote exec timeout in seconds for this endpoint (overrides the global default). */
  timeout?: number;
}

interface RemoteConfig {
  activeEndpoint?: string;
  endpoints?: Record<string, RemoteEndpointConfig>;
  displayLines?: number;
  /** Default remote exec timeout in seconds when a tool call does not specify one. */
  defaultTimeout?: number;
  /** Legacy fields migrated into endpoints on the next config write. */
  sshCommand?: string;
  remoteCwd?: string;
  forwards?: string[];
}

interface ForwardSpec {
  localPort: number;
  remoteHost: string;
  remotePort: number;
}

const AGENT_DIR = getAgentDir();
const KNOWN_HOSTS_FILE = join(AGENT_DIR, "ssh-remote-known-hosts.json");
const REMOTE_CONFIG_FILE = join(AGENT_DIR, "ssh-remote-config.json");
const CREDENTIALS_FILE = join(AGENT_DIR, "ssh-remote-credentials.json");
const FALLBACK_REMOTE_CWD = "~";
const DEFAULT_DISPLAY_LINES = 5;
const DEFAULT_REMOTE_TIMEOUT_SECONDS = 600; // 10 min safety net; override per call or per config
const SSH_AGENT_PROBE_TIMEOUT_MS = 2000;
const MAX_REMOTE_TIMEOUT_SECONDS = 2_147_483_647 / 1000;
const ENDPOINT_SELECTOR_DESCRIPTION = "Endpoint full key, exact or unique host/IP prefix, user@host, host:port, or unique note prefix";
const CACHE_KEY = "__piHpcCredentialCacheV1";
const cacheHost = globalThis as typeof globalThis & { [CACHE_KEY]?: CredentialCache };
const credentialCache = cacheHost[CACHE_KEY] ??= { passwords: new Map<string, string>() };
const clientLastErrors = new WeakMap<Client, Error>();

function runCommand(command: string, args: string[], input?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.stdin.on("error", () => {});
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(Buffer.concat(stdout).toString("utf8").trim());
      else reject(new Error(Buffer.concat(stderr).toString("utf8").trim() || `${command} exited with code ${code}`));
    });
    child.stdin.end(input ?? "", "utf8");
  });
}

function runPowerShell(script: string, input: string): Promise<string> {
  return runCommand("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], input);
}

/** Resolve a command on PATH without spawning a process (safe at import time). */
function hasCommand(name: string): boolean {
  const searchPath = process.env.PATH;
  if (!searchPath) return false;
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".EXE").split(";").filter(Boolean)
    : [""];
  return searchPath.split(delimiter).some((dir) => {
    if (!dir) return false;
    return extensions.some((extension) => {
      try {
        accessSync(join(dir, name + extension), fsConstants.X_OK);
        return true;
      } catch {
        return false;
      }
    });
  });
}

export const WINDOWS_DPAPI_PROTECT_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$asm=[System.Reflection.Assembly]::Load('System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')",
  "$t=$asm.GetType('System.Security.Cryptography.ProtectedData')",
  "$scope=[System.Security.Cryptography.DataProtectionScope]::CurrentUser",
  "$b64=[Console]::In.ReadToEnd().Trim()",
  "$plainBytes=[Convert]::FromBase64String($b64)",
  "[Convert]::ToBase64String($t::Protect($plainBytes,$null,$scope))",
].join(";");

export const WINDOWS_DPAPI_UNPROTECT_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$asm=[System.Reflection.Assembly]::Load('System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')",
  "$t=$asm.GetType('System.Security.Cryptography.ProtectedData')",
  "$scope=[System.Security.Cryptography.DataProtectionScope]::CurrentUser",
  "$cipher=[Console]::In.ReadToEnd().Trim()",
  "$plainBytes=$t::Unprotect([Convert]::FromBase64String($cipher),$null,$scope)",
  "[Convert]::ToBase64String($plainBytes)",
].join(";");

// ---- credential backends ----------------------------------------------------
//
// Each backend stores one endpoint password. Secrets live either inside
// `ssh-remote-credentials.json` (self-contained ciphertext, tagged with the
// backend id) or, for OS keystores, in the keychain itself with only a small
// tag left in the file.

const CREDENTIAL_TAG_SEPARATOR = ":";
const WINDOWS_DPAPI_CODEC_ID = "dpapi";
const MAC_KEYCHAIN_CODEC_ID = "keychain";
const LIBSECRET_CODEC_ID = "libsecret";
const FILE_CODEC_ID = "file";
const OS_KEYSTORE_SERVICE = "pi-ssh-remote";
const KEY_FILE_PATH = join(AGENT_DIR, "ssh-remote-secret.key");
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const KEY_FILE_BYTES = 32;

const windowsDpapiCodec: SecretCodec = {
  id: WINDOWS_DPAPI_CODEC_ID,
  label: "Windows DPAPI",
  available: process.platform === "win32",
  async protect(_endpointId, secret) {
    return runPowerShell(WINDOWS_DPAPI_PROTECT_SCRIPT, Buffer.from(secret, "utf8").toString("base64"));
  },
  async unprotect(_endpointId, ciphertext) {
    const encoded = await runPowerShell(WINDOWS_DPAPI_UNPROTECT_SCRIPT, ciphertext);
    return Buffer.from(encoded, "base64").toString("utf8");
  },
};

const macKeychainCodec: SecretCodec = {
  id: MAC_KEYCHAIN_CODEC_ID,
  label: "macOS Keychain",
  available: process.platform === "darwin" && hasCommand("security"),
  async protect(endpointId, secret) {
    await runCommand("security", ["add-generic-password", "-U", "-s", OS_KEYSTORE_SERVICE, "-a", endpointId, "-w", secret]);
    return "";
  },
  async unprotect(endpointId) {
    const secret = await runCommand("security", ["find-generic-password", "-s", OS_KEYSTORE_SERVICE, "-a", endpointId, "-w"]);
    if (!secret) throw new Error("macOS Keychain returned an empty secret");
    return secret;
  },
  async remove(endpointId) {
    await runCommand("security", ["delete-generic-password", "-s", OS_KEYSTORE_SERVICE, "-a", endpointId]);
  },
};

const libsecretCodec: SecretCodec = {
  id: LIBSECRET_CODEC_ID,
  label: "libsecret / Secret Service",
  available: process.platform !== "win32" && hasCommand("secret-tool"),
  async protect(endpointId, secret) {
    await runCommand(
      "secret-tool",
      ["store", "--label", `${OS_KEYSTORE_SERVICE} ${endpointId}`, "service", OS_KEYSTORE_SERVICE, "account", endpointId],
      secret,
    );
    return "";
  },
  async unprotect(endpointId) {
    const secret = await runCommand("secret-tool", ["lookup", "service", OS_KEYSTORE_SERVICE, "account", endpointId]);
    if (!secret) throw new Error("secret-tool returned no stored secret (locked or missing keyring?)");
    return secret;
  },
  async remove(endpointId) {
    await runCommand("secret-tool", ["clear", "service", OS_KEYSTORE_SERVICE, "account", endpointId]);
  },
};

/**
 * Portable fallback backend: AES-256-GCM keyed by a random key kept in a 0600
 * file next to the credential store. Passwords never appear in plaintext in
 * `ssh-remote-credentials.json` (so backups, dotfile sync or a pasted config
 * cannot leak them), but the key file sits in the same directory: this is
 * weaker than an OS keystore and only protects the credential file itself.
 */
export function createFileKeyCodec(keyPath: string): SecretCodec {
  let cachedKey: Buffer | undefined;

  const readKey = (): Buffer => {
    const key = Buffer.from(readFileSync(keyPath, "utf8").trim(), "hex");
    if (key.length !== KEY_FILE_BYTES) throw new Error(`credential key file ${keyPath} is not a ${KEY_FILE_BYTES}-byte hex key`);
    return key;
  };

  const loadKey = (): Buffer => {
    if (cachedKey) return cachedKey;
    try {
      const existing = readKey();
      try { chmodSync(keyPath, 0o600); } catch {}
      cachedKey = existing;
      return existing;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    mkdirSync(dirname(keyPath), { recursive: true });
    const key = randomBytes(KEY_FILE_BYTES);
    try {
      writeFileSync(keyPath, `${key.toString("hex")}\n`, { mode: 0o600, flag: "wx" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      // Another Pi process created the key first: reuse it instead of forking the store.
      cachedKey = readKey();
      return cachedKey;
    }
    try { chmodSync(keyPath, 0o600); } catch {}
    cachedKey = key;
    return key;
  };

  return {
    id: FILE_CODEC_ID,
    label: "encrypted key file",
    available: true,
    async protect(endpointId, secret) {
      const iv = randomBytes(AES_GCM_IV_BYTES);
      const cipher = createCipheriv("aes-256-gcm", loadKey(), iv, { authTagLength: AES_GCM_TAG_BYTES });
      cipher.setAAD(Buffer.from(endpointId, "utf8"));
      const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64");
    },
    async unprotect(endpointId, payload) {
      const raw = Buffer.from(payload, "base64");
      if (raw.length <= AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES) throw new Error("credential payload is truncated");
      const decipher = createDecipheriv("aes-256-gcm", loadKey(), raw.subarray(0, AES_GCM_IV_BYTES), { authTagLength: AES_GCM_TAG_BYTES });
      decipher.setAAD(Buffer.from(endpointId, "utf8"));
      decipher.setAuthTag(raw.subarray(AES_GCM_IV_BYTES, AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES));
      return Buffer.concat([decipher.update(raw.subarray(AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES)), decipher.final()]).toString("utf8");
    },
  };
}

const fileKeyCodec = createFileKeyCodec(KEY_FILE_PATH);

/**
 * Backends in preference order. OS keystores come first; the local encrypted
 * key file is always last so persistence keeps working on headless Linux,
 * containers and any platform without a usable keyring.
 */
export function resolveCredentialCodecs(): SecretCodec[] {
  const codecs = [windowsDpapiCodec, macKeychainCodec, libsecretCodec].filter((codec) => codec.available);
  codecs.push(fileKeyCodec);
  return codecs;
}

export class PersistentCredentialStore {
  constructor(
    private readonly path: string,
    private readonly codecs: SecretCodec[] = [],
  ) {}

  /** Labels of the backends usable in this environment, primary first. */
  get backends(): string[] { return this.codecs.filter((codec) => codec.available).map((codec) => codec.label); }

  /** Preferred backend label. */
  get label(): string { return this.backends[0] ?? "no credential backend"; }

  get available(): boolean { return Boolean(this.backends.length); }

  private codecById(id: string): SecretCodec | undefined {
    return this.codecs.find((codec) => codec.id === id);
  }

  /** Values written before backend tagging are Windows DPAPI ciphertext. */
  private static split(raw: string): { codecId: string; payload: string } {
    const index = raw.indexOf(CREDENTIAL_TAG_SEPARATOR);
    if (index < 0) return { codecId: WINDOWS_DPAPI_CODEC_ID, payload: raw };
    return { codecId: raw.slice(0, index), payload: raw.slice(index + 1) };
  }

  /** Backend label that owns this endpoint's stored secret, if it is readable now. */
  backendFor(id: string): string | undefined {
    const raw = this.load().passwords[id];
    if (!raw) return undefined;
    const codec = this.codecById(PersistentCredentialStore.split(raw).codecId);
    return codec?.available ? codec.label : undefined;
  }

  private load(): PersistentCredentialFile {
    try {
      const parsed = JSON.parse(readFileSync(this.path, "utf8")) as Partial<PersistentCredentialFile>;
      if (parsed.version !== 1 || !parsed.passwords || typeof parsed.passwords !== "object") throw new Error("Invalid credential file");
      return { version: 1, passwords: { ...parsed.passwords } };
    } catch {
      return { version: 1, passwords: {} };
    }
  }

  private save(file: PersistentCredentialFile): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(file, null, 2) + "\n", { mode: 0o600 });
  }

  has(id: string): boolean {
    const raw = this.load().passwords[id];
    if (!raw) return false;
    return Boolean(this.codecById(PersistentCredentialStore.split(raw).codecId)?.available);
  }

  async get(id: string): Promise<string | undefined> {
    const raw = this.load().passwords[id];
    if (!raw) return undefined;
    const { codecId, payload } = PersistentCredentialStore.split(raw);
    const codec = this.codecById(codecId);
    if (!codec?.available) return undefined;
    try {
      return await codec.unprotect(id, payload);
    } catch {
      return undefined;
    }
  }

  /** Try each backend in order until one saves the secret. */
  async set(id: string, password: string): Promise<{ persisted: boolean; backend?: string; error?: string }> {
    const failures: string[] = [];
    for (const codec of this.codecs) {
      if (!codec.available) continue;
      try {
        const payload = await codec.protect(id, password);
        const file = this.load();
        file.passwords[id] = `${codec.id}${CREDENTIAL_TAG_SEPARATOR}${payload}`;
        this.save(file);
        return { persisted: true, backend: codec.label };
      } catch (error) {
        failures.push(`${codec.label}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    return { persisted: false, error: failures.join("; ") || "no credential backend available" };
  }

  delete(id: string): boolean {
    const file = this.load();
    const raw = file.passwords[id];
    if (!raw) return false;
    delete file.passwords[id];
    this.save(file);
    this.removeFromBackend(id, PersistentCredentialStore.split(raw).codecId);
    return true;
  }

  clear(): number {
    const file = this.load();
    const ids = Object.keys(file.passwords);
    if (!ids.length) return 0;
    const tags = ids.map((id) => PersistentCredentialStore.split(file.passwords[id]!).codecId);
    this.save({ version: 1, passwords: {} });
    ids.forEach((id, index) => this.removeFromBackend(id, tags[index]!));
    return ids.length;
  }

  /** Keychain-backed secrets live outside the JSON file; drop them best-effort. */
  private removeFromBackend(id: string, codecId: string): void {
    const codec = this.codecById(codecId);
    if (!codec?.remove) return;
    try {
      void Promise.resolve(codec.remove(id)).catch(() => {});
    } catch {
      // Best effort only: the credential file no longer references the secret.
    }
  }
}

const persistentCredentials = new PersistentCredentialStore(CREDENTIALS_FILE, resolveCredentialCodecs());

export function probeSshAgent(socketPath: string, timeoutMs = SSH_AGENT_PROBE_TIMEOUT_MS): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (usable: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(usable);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    try {
      createAgent(socketPath).getIdentities((error, identities) => {
        finish(!error && Array.isArray(identities) && identities.length > 0);
      });
    } catch {
      finish(false);
    }
  });
}

async function usableSshAgentPath(): Promise<string | undefined> {
  const socketPath = process.env.SSH_AUTH_SOCK?.trim();
  if (!socketPath) return undefined;
  return await probeSshAgent(socketPath) ? socketPath : undefined;
}

function shellWords(input: string): string[] {
  const words: string[] = [];
  let word = "";
  let quoteChar: "'" | '"' | null = null;
  let escaped = false;
  for (const ch of input.trim()) {
    if (escaped) { word += ch; escaped = false; continue; }
    if (ch === "\\" && quoteChar !== "'") { escaped = true; continue; }
    if (quoteChar) { if (ch === quoteChar) quoteChar = null; else word += ch; continue; }
    if (ch === "'" || ch === '"') { quoteChar = ch; continue; }
    if (/\s/.test(ch)) { if (word) { words.push(word); word = ""; } }
    else word += ch;
  }
  if (escaped || quoteChar) throw new Error("Incomplete quoting or escaping in SSH command");
  if (word) words.push(word);
  return words;
}

function parseSshCommand(command: string): ParsedSsh {
  const args = shellWords(command);
  if (args[0] !== "ssh") throw new Error("Command must start with ssh, for example: ssh root@host -p 22");
  let port = 22;
  let username = process.env.USER || "root";
  let target: string | undefined;
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "-p") { port = Number(args[++i]); continue; }
    if (arg.startsWith("-p") && arg.length > 2) { port = Number(arg.slice(2)); continue; }
    if (arg === "-l") { username = args[++i] || username; continue; }
    if (arg.startsWith("-")) throw new Error(`Unsupported SSH option ${arg}; only -p and -l are currently supported`);
    if (!target) target = arg;
    else throw new Error("Unexpected extra argument in SSH command");
  }
  if (!target || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid SSH host or port");
  const at = target.lastIndexOf("@");
  const host = at >= 0 ? target.slice(at + 1) : target;
  if (at >= 0) username = target.slice(0, at);
  if (!host || !username) throw new Error("Invalid SSH username or host");
  return { host, port, username, label: `${username}@${host}:${port}`, command };
}

function cacheId(config: ParsedSsh): string {
  return `${config.username}@${config.host}:${config.port}`;
}

/**
 * Canonical endpoint key shape: `user@host:port`.
 * Selectors are deliberately forgiving because the model (and the user) often
 * retypes an address instead of copying the exact key from the endpoint list.
 */
const ENDPOINT_KEY_RE = /^([^@\s]+)@([^:\s]+):(\d+)$/;

/** Trim decoration models tend to add: quotes, backticks, an `ssh ` prefix, ssh flags. */
export function normalizeEndpointSelector(requested: string): string {
  let value = requested.trim().replace(/^[\s"'`]+|[\s"'`]+$/g, "");
  if (/^ssh\s+/i.test(value)) value = value.replace(/^ssh\s+/i, "").trim();
  const words = value.split(/\s+/);
  if (words.length > 1) {
    const positional: string[] = [];
    for (let index = 0; index < words.length; index += 1) {
      const word = words[index]!;
      if (word === "-p" || word === "-l") { index += 1; continue; }
      if (word.startsWith("-")) continue;
      positional.push(word);
    }
    if (positional.length === 1) value = positional[0]!;
  }
  return value.trim().toLowerCase();
}

/** Split a selector into host/port, ignoring a username that may be wrong. */
function selectorAddress(requested: string): { host: string; port?: string } | undefined {
  const at = requested.lastIndexOf("@");
  let rest = at >= 0 ? requested.slice(at + 1) : requested;
  if (!rest) return undefined;
  let port: string | undefined;
  const colon = rest.match(/^(.*):(\d+)$/);
  if (colon) { rest = colon[1]!; port = colon[2]!; }
  if (!rest || /[\s/]/.test(rest)) return undefined;
  return { host: rest, ...(port ? { port } : {}) };
}

/**
 * Resolve a selector against configured endpoint keys, best tier first.
 * Every tier returns *all* matches, so the caller reports ambiguity instead of
 * silently picking a server.
 */
export function endpointSelectorMatches(
  keys: string[],
  endpoints: Record<string, { note?: string } | undefined>,
  requested: string,
): string[] {
  const needle = normalizeEndpointSelector(requested);
  if (!needle) return [];
  const aliases = (key: string): string[] => {
    const match = key.match(ENDPOINT_KEY_RE);
    const endpoint = endpoints[key];
    const values = [key];
    if (match) {
      const [, username, host, port] = match;
      values.push(host!, `${host}:${port}`, `${username}@${host}`);
    }
    if (endpoint?.note?.trim()) values.push(endpoint.note.trim());
    return values.map((value) => value.toLowerCase());
  };
  const unique = (matches: string[]): string[] => (matches.length ? [...new Set(matches)] : []);

  // 1. Exact key, host, host:port, user@host or note.
  const exact = unique(keys.filter((key) => aliases(key).some((alias) => alias === needle)));
  if (exact.length) return exact;

  // 2. Same address with a different or absent username: `root@IP` is what the
  //    model invents when it retypes a server instead of copying the key.
  const address = selectorAddress(needle);
  if (address && (address.host.includes(".") || /[a-z]/i.test(address.host))) {
    const byAddress = unique(keys.filter((key) => {
      const match = key.match(ENDPOINT_KEY_RE);
      if (!match) return false;
      const [, , host, port] = match;
      if (host!.toLowerCase() !== address.host) return false;
      return !address.port || address.port === port;
    }));
    if (byAddress.length) return byAddress;
  }

  // 3. Note substring ("work15", "master", "A5 box") when it is unambiguous.
  const byNote = unique(keys.filter((key) => endpoints[key]?.note?.toLowerCase().includes(needle)));
  if (byNote.length) return byNote;

  // 4. Trailing octet ("21", ".21") as in "the server ending in .21".
  const octet = needle.replace(/^\./, "");
  if (/^\d{1,3}$/.test(octet)) {
    const byOctet = unique(keys.filter((key) => {
      const match = key.match(ENDPOINT_KEY_RE);
      return match ? match[2]!.toLowerCase().endsWith(`.${octet}`) : false;
    }));
    if (byOctet.length) return byOctet;
  }

  // 5. Legacy prefix match on any alias.
  const prefix = unique(keys.filter((key) => aliases(key).some((alias) => alias.startsWith(needle))));
  if (prefix.length) return prefix;

  // 6. Last resort: substring on key / host / user@host.
  return unique(keys.filter((key) => aliases(key).slice(0, 4).some((alias) => alias.includes(needle))));
}

/** Actionable error text for the agent when a selector does not resolve. */
export function describeEndpointResolutionFailure(
  requested: string,
  keys: string[],
  endpoints: Record<string, { note?: string } | undefined>,
  connected: Set<string>,
  connectedOnly: boolean,
  matches: string[] = [],
): string {
  const shown = keys.slice(0, 25).map((key) => {
    const note = endpoints[key]?.note?.trim();
    const flags = [connected.has(key) ? "connected" : "configured", note].filter(Boolean).join("; ");
    return `  - ${key}${flags ? `  (${flags})` : ""}`;
  });
  const more = keys.length > shown.length ? `\n  ...and ${keys.length - shown.length} more` : "";
  const list = keys.length
    ? `Known endpoints:\n${shown.join("\n")}${more}`
    : "No endpoints are configured yet; connect one with ssh_remote_control action=connect.";
  if (matches.length > 1) {
    return `Endpoint selector is ambiguous: "${requested}" matches ${matches.join(", ")}. Pass one of those keys exactly.\n${list}`;
  }
  if (connectedOnly) {
    return `Endpoint not found or not connected: "${requested}". Reconnect it first (ssh_remote_control action=connect or action=reconnect), or pick a connected endpoint.\n${list}`;
  }
  return `Endpoint not found: "${requested}". Use an exact key from the list below, or an unambiguous part of it (host/IP, host:port, user@host, or note). Do not invent an IP; if the endpoint is missing, call ssh_remote_control action=connect first.\n${list}`;
}

async function getCachedPassword(config: ParsedSsh): Promise<string | undefined> {
  const id = cacheId(config);
  const memoryPassword = credentialCache.passwords.get(id);
  if (memoryPassword !== undefined) return memoryPassword;
  const persistentPassword = await persistentCredentials.get(id);
  if (persistentPassword !== undefined) credentialCache.passwords.set(id, persistentPassword);
  return persistentPassword;
}

async function setCachedPassword(config: ParsedSsh, password: string): Promise<{ persisted: boolean; backend?: string; error?: string }> {
  const id = cacheId(config);
  credentialCache.passwords.set(id, password);
  try { return await persistentCredentials.set(id, password); }
  catch (error) { return { persisted: false, error: error instanceof Error ? error.message : String(error) }; }
}

function deleteCachedPassword(config: ParsedSsh): void {
  deleteCachedPasswordById(cacheId(config));
}

function deleteCachedPasswordById(id: string): void {
  credentialCache.passwords.delete(id);
  try { persistentCredentials.delete(id); }
  catch {}
}

function clearCachedPasswords(): number {
  const ids = new Set([...credentialCache.passwords.keys()]);
  credentialCache.passwords.clear();
  try {
    const persistentCount = persistentCredentials.clear();
    return Math.max(ids.size, persistentCount);
  } catch {
    return ids.size;
  }
}

function parseForwardSpec(value: string): ForwardSpec {
  const match = value.match(/^(\d+):([^:]+):(\d+)$/);
  if (!match) throw new Error(`Invalid port-forward specification: ${value}; expected LOCAL_PORT:REMOTE_HOST:REMOTE_PORT`);
  const localPort = Number(match[1]);
  const remoteHost = match[2]!;
  const remotePort = Number(match[3]);
  if (![localPort, remotePort].every((port) => Number.isInteger(port) && port > 0 && port <= 65535)) {
    throw new Error(`Port out of range in forwarding specification: ${value}`);
  }
  return { localPort, remoteHost, remotePort };
}

function quote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function parseDisplayLines(value: unknown): number {
  const lines = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(lines) || lines < 1 || lines > DEFAULT_MAX_LINES) {
    throw new Error(`Display lines must be an integer from 1 to ${DEFAULT_MAX_LINES}`);
  }
  return lines;
}

function parseRemoteTimeout(value: unknown): number {
  const seconds = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds > MAX_REMOTE_TIMEOUT_SECONDS) {
    throw new Error(`Timeout must be a positive number no greater than ${MAX_REMOTE_TIMEOUT_SECONDS} seconds`);
  }
  return seconds;
}

function withRemoteTimeout(command: string, timeoutSeconds: number): string {
  return `timeout --signal=TERM --kill-after=5s ${timeoutSeconds}s bash -lc ${quote(command)}`;
}

function configuredDisplayLines(config = loadRemoteConfig()): number {
  try { return parseDisplayLines(config.displayLines ?? DEFAULT_DISPLAY_LINES); }
  catch { return DEFAULT_DISPLAY_LINES; }
}

/** Resolve the default remote timeout: per-endpoint config > global config > built-in default. */
function configuredRemoteTimeout(endpointKey?: string, config = loadRemoteConfig()): number {
  try {
    const perEndpoint = endpointKey ? config.endpoints?.[endpointKey]?.timeout : undefined;
    return parseRemoteTimeout(perEndpoint ?? config.defaultTimeout ?? DEFAULT_REMOTE_TIMEOUT_SECONDS);
  }
  catch { return DEFAULT_REMOTE_TIMEOUT_SECONDS; }
}

function commandFromEndpointKey(key: string): string | undefined {
  const match = key.match(/^([^@]+)@(.+):(\d+)$/);
  if (!match) return undefined;
  const [, username, host, port] = match;
  return `ssh ${username}@${host} -p ${port}`;
}

function normalizeRemoteConfig(config: RemoteConfig): RemoteConfig {
  const endpoints = { ...(config.endpoints ?? {}) };
  for (const [key, endpoint] of Object.entries(endpoints)) {
    // Whitelist known fields so legacy `$`-passthrough keys disappear on the next save.
    endpoints[key] = {
      ...(endpoint.sshCommand || commandFromEndpointKey(key) ? { sshCommand: endpoint.sshCommand || commandFromEndpointKey(key) } : {}),
      ...(endpoint.remoteCwd !== undefined ? { remoteCwd: endpoint.remoteCwd } : {}),
      ...(endpoint.forwards !== undefined ? { forwards: endpoint.forwards } : {}),
      ...(endpoint.note !== undefined ? { note: endpoint.note } : {}),
      ...(endpoint.timeout !== undefined ? { timeout: endpoint.timeout } : {}),
    };
  }

  let activeEndpoint = config.activeEndpoint;
  if (config.sshCommand) {
    try {
      const key = cacheId(parseSshCommand(config.sshCommand));
      endpoints[key] = {
        ...(endpoints[key] ?? {}),
        sshCommand: config.sshCommand,
        ...(config.remoteCwd !== undefined ? { remoteCwd: config.remoteCwd } : {}),
        ...(config.forwards !== undefined ? { forwards: config.forwards } : {}),
      };
      activeEndpoint ??= key;
    } catch {}
  }
  if (activeEndpoint && !endpoints[activeEndpoint]) activeEndpoint = undefined;
  activeEndpoint ??= Object.keys(endpoints)[0];
  let displayLines: number | undefined;
  try { displayLines = config.displayLines === undefined ? undefined : parseDisplayLines(config.displayLines); }
  catch { displayLines = undefined; }
  let defaultTimeout: number | undefined;
  try { defaultTimeout = config.defaultTimeout === undefined ? undefined : parseRemoteTimeout(config.defaultTimeout); }
  catch { defaultTimeout = undefined; }

  return {
    ...(activeEndpoint ? { activeEndpoint } : {}),
    ...(Object.keys(endpoints).length ? { endpoints } : {}),
    ...(displayLines !== undefined ? { displayLines } : {}),
    ...(defaultTimeout !== undefined ? { defaultTimeout } : {}),
  };
}

function loadRemoteConfig(): RemoteConfig {
  try { return normalizeRemoteConfig(JSON.parse(readFileSync(REMOTE_CONFIG_FILE, "utf8"))); }
  catch { return {}; }
}

function saveRemoteConfig(config: RemoteConfig): void {
  mkdirSync(dirname(REMOTE_CONFIG_FILE), { recursive: true });
  writeFileSync(REMOTE_CONFIG_FILE, JSON.stringify(normalizeRemoteConfig(config), null, 2) + "\n", { mode: 0o600 });
}

function endpointConfig(config: RemoteConfig, command: string): RemoteEndpointConfig {
  try { return config.endpoints?.[cacheId(parseSshCommand(command))] ?? {}; }
  catch { return {}; }
}

function activeEndpointConfig(config: RemoteConfig): RemoteEndpointConfig | undefined {
  return config.activeEndpoint ? config.endpoints?.[config.activeEndpoint] : undefined;
}

function activeSshCommand(config = loadRemoteConfig()): string | undefined {
  return activeEndpointConfig(config)?.sshCommand;
}

function endpointDisplayLabel(endpoint: ParsedSsh, config = loadRemoteConfig()): string {
  const note = endpointConfig(config, endpoint.command).note?.trim();
  return note ? `${note} (${endpoint.label})` : endpoint.label;
}

function saveEndpointConfig(command: string, updates: RemoteEndpointConfig, makeActive = false): void {
  const config = loadRemoteConfig();
  const key = cacheId(parseSshCommand(command));
  saveRemoteConfig({
    ...config,
    ...(makeActive ? { activeEndpoint: key } : {}),
    endpoints: {
      ...(config.endpoints ?? {}),
      [key]: { ...endpointConfig(config, command), sshCommand: command, ...updates },
    },
  });
}

function loadKnownHosts(): Record<string, string> {
  try { return JSON.parse(readFileSync(KNOWN_HOSTS_FILE, "utf8")); }
  catch { return {}; }
}

function saveKnownHost(key: string, fingerprint: string): void {
  const hosts = loadKnownHosts();
  hosts[key] = fingerprint;
  mkdirSync(dirname(KNOWN_HOSTS_FILE), { recursive: true });
  writeFileSync(KNOWN_HOSTS_FILE, JSON.stringify(hosts, null, 2) + "\n", { mode: 0o600 });
}

function displayFingerprint(hex: string): string {
  return `SHA256:${Buffer.from(hex, "hex").toString("base64").replace(/=+$/, "")}`;
}

/** Strips PTY artifacts (\r from CRLF, ANSI/terminal control sequences) so output previews stay clean. */
function sanitizePtyOutput(output: string): string {
  // ANSI CSI sequences: ESC [ ... final byte, plus OSC (ESC ] ... BEL/ST) and two-char sequences (cursor, save/restore).
  // eslint-disable-next-line no-control-regex
  return output
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, "")
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b[()][0-9A-Za-z]/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "");
}

function formatRemoteOutput(output: string) {
  const clean = sanitizePtyOutput(output);
  const truncation = truncateTail(clean, { maxLines: DEFAULT_MAX_LINES, maxBytes: DEFAULT_MAX_BYTES });
  const content = truncation.content || "Remote command completed.";
  if (!truncation.truncated) return { text: content, content, truncation };

  const outputDir = mkdtempSync(join(tmpdir(), "pi-ssh-remote-output-"));
  const fullOutputPath = join(outputDir, "output.log");
  writeFileSync(fullOutputPath, clean, { encoding: "utf8", mode: 0o600 });
  const startLine = truncation.totalLines - truncation.outputLines + 1;
  const limit = truncation.truncatedBy === "bytes" ? ` (${formatSize(DEFAULT_MAX_BYTES)} limit)` : "";
  const text = `${content}\n\n[Showing lines ${startLine}-${truncation.totalLines} of ${truncation.totalLines}${limit}. Full output: ${fullOutputPath}]`;
  return { text, content, truncation, fullOutputPath };
}

function previewRemoteOutput(output: string, displayLines: number): string {
  return truncateTail(sanitizePtyOutput(output), { maxLines: displayLines, maxBytes: DEFAULT_MAX_BYTES }).content || "Remote command completed.";
}

function renderRemoteControlResult(result: any, expanded: boolean, theme: any): Component {
  const fallback = result.content?.find((item: any) => item.type === "text")?.text ?? "";
  const details = result.details;
  if (details?.action !== "exec") return new Text(fallback, 0, 0);

  const output = details.output || fallback;
  const displayLines = details.displayLines || DEFAULT_DISPLAY_LINES;
  const warnings = [
    ...(details.fullOutputPath ? [`Full output: ${details.fullOutputPath}`] : []),
    ...(details.truncation?.truncated ? [`Truncated: showing ${details.truncation.outputLines} of ${details.truncation.totalLines} lines`] : []),
  ];
  const warning = warnings.length ? warnings.join(". ") : undefined;

  if (expanded) {
    return new Text(`${output}${warning ? `\n${theme.fg("warning", `[${warning}]`)}` : ""}`, 0, 0);
  }

  return {
    render(width: number) {
      const styled = output.split("\n").map((line: string) => theme.fg("toolOutput", line)).join("\n");
      const visualLines = new Text(styled, 0, 0).render(width);
      const shown = visualLines.slice(-displayLines);
      const skipped = visualLines.length - shown.length;
      const hint = skipped > 0
        ? [theme.fg("muted", `... (${skipped} earlier lines, ${keyHint("app.tools.expand", "to expand")})`)]
        : [];
      return [...hint, ...shown, ...(warning ? [theme.fg("warning", `[${warning}]`)] : [])];
    },
    invalidate() {},
  };
}

const EXEC_UPDATE_THROTTLE_MS = 250;
const EXEC_KEEP_BYTES = 64 * 1024;

/**
 * Cumulative streaming output reporter for exec-style tools. Buffers recent
 * chunks and pushes a throttled tail preview through the tool onUpdate
 * callback so the TUI can render live progress (same protocol as built-in
 * bash's OutputAccumulator updates).
 */
class ExecStreamProgress {
  private chunks: Buffer[] = [];
  private keptBytes = 0;
  private totalBytes = 0;
  private lastEmit = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private closed = false;

  constructor(
    private readonly onUpdate: ((update: { content: Array<{ type: "text"; text: string }>; details: unknown }) => void) | undefined,
    private readonly maxLines: number,
  ) {
  }

  append(chunk: Buffer): void {
    this.totalBytes += chunk.length;
    this.chunks.push(chunk);
    this.keptBytes += chunk.length;
    while (this.keptBytes > EXEC_KEEP_BYTES && this.chunks.length > 1) {
      this.keptBytes -= (this.chunks.shift() as Buffer).length;
    }
    if (!this.onUpdate || this.closed) return;
    const delay = EXEC_UPDATE_THROTTLE_MS - (Date.now() - this.lastEmit);
    if (delay <= 0) {
      this.emit();
      return;
    }
    this.timer ??= setTimeout(() => {
      this.timer = undefined;
      this.emit();
    }, delay);
  }

  /** Best-effort tail text for error messages ("Command aborted" etc.). */
  tail(): string {
    const preview = previewRemoteOutput(Buffer.concat(this.chunks).toString("utf8"), this.maxLines);
    const dropped = this.totalBytes - this.keptBytes;
    return dropped > 0 ? `[... ${formatSize(dropped)} of earlier output omitted ...]\n${preview}` : preview;
  }

  /** Final flush, then stop emitting. */
  finish(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    this.emit();
    this.closed = true;
  }

  private emit(): void {
    if (!this.onUpdate || this.closed) return;
    this.lastEmit = Date.now();
    this.onUpdate({ content: [{ type: "text", text: this.tail() }], details: undefined });
  }
}

/** Shared renderCall for exec-style tools: shows endpoint and the remote command. */
function renderRemoteExecCall(title: string, args: any, theme: any): Component {
  const endpoint = typeof args?.endpoint === "string" ? args.endpoint : "";
  const command = typeof args?.command === "string" ? args.command.replace(/\s+/g, " ").trim() : "";
  const head = theme.fg("toolTitle", theme.bold(`${title} `)) + (endpoint ? theme.fg("muted", endpoint) : "");
  if (!command) return new Text(head, 0, 0);
  return new Text(`${head}\n${theme.fg("muted", "$")} ${theme.fg("toolOutput", truncateToWidth(command, 200))}`, 0, 0);
}

export function probeFingerprint(config: ParsedSsh): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; client.end(); reject(new Error("Connection timed out")); }
    }, 10000);
    client.on("error", (error) => {
      if (!settled) { settled = true; clearTimeout(timer); reject(error); }
    });
    client.connect({
      host: config.host,
      port: config.port,
      username: config.username,
      readyTimeout: 8000,
      hostHash: "sha256",
      hostVerifier: (hash: string) => {
        if (!settled) { settled = true; clearTimeout(timer); resolve(hash); }
        setImmediate(() => client.end());
        return false;
      },
    });
  });
}

export async function connect(config: ParsedSsh, password: string | undefined, fingerprint: string): Promise<Client> {
  const agentPath = await usableSshAgentPath();
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    const options: ConnectConfig = {
      host: config.host,
      port: config.port,
      username: config.username,
      ...(password ? { password } : {}),
      ...(agentPath ? { agent: agentPath } : {}),
      readyTimeout: 12000,
      keepaliveInterval: 15000,
      keepaliveCountMax: 3,
      hostHash: "sha256",
      hostVerifier: (hash: string) => hash === fingerprint,
    };
    client.on("error", (error: Error & { level?: string }) => {
      clientLastErrors.set(client, error);
      // ssh2 emits an intermediate `error` when an agent is unavailable and
      // then continues to the next authentication method. Consuming that
      // event is required: a one-shot listener would be removed here and the
      // later terminal authentication error would crash Node as an unhandled
      // EventEmitter `error` event.
      if (error.level === "agent") return;
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    client.once("ready", () => {
      if (settled) return;
      settled = true;
      resolve(client);
    });
    try { client.connect(options); }
    catch (error) {
      settled = true;
      reject(error);
    }
  });
}

/** Optional hooks for cancellation and streaming output previews. */
interface ExecHooks {
  /** AbortSignal: when aborted the SSH channel is interrupted (SIGINT under PTY) and closed; the promise rejects with "aborted". */
  signal?: AbortSignal;
  /** Called for every stdout/stderr chunk as it arrives (for live progress rendering). */
  onData?: (chunk: Buffer) => void;
  /** Bytes written to remote stdin once the exec channel opens, then stdin is closed. */
  stdin?: string | Buffer;
  /** Allocate a remote pseudo-terminal: gives full Ctrl+C (SIGINT to the foreground process group) and SIGHUP-on-close semantics. Default true for exec-style tools. PTY merges stderr into stdout and adds CRLF/ANSI noise, which is cleaned before previewing. */
  pty?: boolean;
}

interface ExecRemoteResult {
  /** Raw stdout (PTY channels already merge stderr into stdout). */
  output: Buffer;
  /** Separate stderr buffer, only populated for non-PTY channels. */
  stderr: Buffer;
  /** Remote exit code, or null when the channel closed without reporting one. */
  exitCode: number | null;
  /** True when the local side aborted (Esc) and interrupted the remote process. */
  aborted: boolean;
  /** True when the local wall-clock guard or the remote `timeout` wrapper fired. */
  timedOut: boolean;
  /** Resolved timeout in seconds, for caller-facing messages. */
  timeoutSeconds: number;
}

/**
 * Run a command and report the exit code plus abort/timeout state instead of
 * throwing. `execRemote` is the throwing convenience wrapper on top of this.
 * Rejects only for transport-level stream errors.
 */
function execRemoteDetailed(
  client: Client,
  command: string,
  timeoutSeconds = DEFAULT_REMOTE_TIMEOUT_SECONDS,
  hooks?: ExecHooks,
): Promise<ExecRemoteResult> {
  const resolvedTimeout = parseRemoteTimeout(timeoutSeconds);
  const withPty = hooks?.pty !== false;
  return new Promise((resolve, reject) => {
    if (hooks?.signal?.aborted) {
      return resolve({
        output: Buffer.alloc(0), stderr: Buffer.alloc(0), exitCode: null,
        aborted: true, timedOut: false, timeoutSeconds: resolvedTimeout,
      });
    }
    // ssh2 >=1.17 dereferences opts.allowHalfOpen unconditionally, so a non-PTY
    // exec must pass {} rather than undefined.
    const execOptions: any = withPty ? { pty: { term: "xterm", rows: 40, cols: 160 } } : {};
    client.exec(withRemoteTimeout(command, resolvedTimeout), execOptions, (error, stream) => {
      if (error) return reject(error);
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let locallyTimedOut = false;
      let aborted = false;
      let abortTimer: ReturnType<typeof setTimeout> | undefined;
      const timer = setTimeout(() => {
        locallyTimedOut = true;
        stream.close();
      }, (resolvedTimeout + 8) * 1000);
      const onAbort = () => {
        if (aborted) return;
        aborted = true;
        // Interrupt the remote process group first (real Ctrl+C under PTY),
        // then close the channel after a short grace period so the remote side
        // can flush / die cleanly instead of being SIGPIPE'd mid-write.
        try { stream.signal("INT"); } catch { /* ignore */ }
        abortTimer = setTimeout(() => stream.close(), 1200);
      };
      hooks?.signal?.addEventListener("abort", onAbort, { once: true });
      // The channel may have opened after Esc was already pressed.
      if (hooks?.signal?.aborted) onAbort();
      const cleanup = () => {
        clearTimeout(timer);
        if (abortTimer) clearTimeout(abortTimer);
        hooks?.signal?.removeEventListener("abort", onAbort);
      };
      const handleData = (chunk: Buffer) => {
        // Under PTY, ssh2 surfaces stdout+stderr on the same channel with CRLF
        // line endings; normalise so downstream formatting sees plain text.
        stdout.push(chunk);
        hooks?.onData?.(chunk);
      };
      stream.on("data", handleData);
      // Non-PTY channels get a separate stderr stream; PTY merges it already.
      if (stream.stderr) {
        stream.stderr.on("data", (chunk: Buffer) => {
          stderr.push(chunk);
          hooks?.onData?.(chunk);
        });
      }
      stream.once("error", (streamError: Error) => {
        cleanup();
        // A stream error while the user was aborting is expected, not a failure.
        if (aborted || hooks?.signal?.aborted) {
          resolve({
            output: Buffer.concat(stdout), stderr: Buffer.concat(stderr), exitCode: null,
            aborted: true, timedOut: false, timeoutSeconds: resolvedTimeout,
          });
        } else reject(streamError);
      });
      stream.on("close", (code: number | null) => {
        cleanup();
        resolve({
          output: Buffer.concat(stdout),
          stderr: Buffer.concat(stderr),
          exitCode: code ?? null,
          aborted: aborted || Boolean(hooks?.signal?.aborted),
          timedOut: locallyTimedOut || code === 124 || code === 137,
          timeoutSeconds: resolvedTimeout,
        });
      });
      // Used by non-interactive sudo -S: feed the secret only after the channel
      // opens and all terminal listeners are installed, then close stdin.
      if (hooks?.stdin !== undefined) stream.end(hooks.stdin);
    });
  });
}

function execRemote(
  client: Client,
  command: string,
  allowFailure = false,
  timeoutSeconds = DEFAULT_REMOTE_TIMEOUT_SECONDS,
  hooks?: ExecHooks,
): Promise<Buffer> {
  return execRemoteDetailed(client, command, timeoutSeconds, hooks).then((result) => {
    if (result.aborted) throw new Error("aborted");
    if (result.timedOut) throw new Error(`Remote command timed out after ${result.timeoutSeconds} seconds`);
    if (!allowFailure && result.exitCode !== 0) {
      // Under PTY, stderr is merged into stdout, so fall back to the tail
      // of stdout for the error text when there is no separate stderr.
      const stderrText = result.stderr.toString().trim();
      const stdoutText = result.output.toString().replace(/\s+$/, "");
      const tail = stderrText || stdoutText.split("\n").slice(-15).join("\n");
      throw new Error(tail || `Remote command exited with code ${result.exitCode}`);
    }
    return result.output;
  });
}

function getSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => client.sftp((error, sftp) => error ? reject(error) : resolve(sftp)));
}

async function withSftp<T>(client: Client, operation: (sftp: SFTPWrapper) => Promise<T>): Promise<T> {
  const sftp = await getSftp(client);
  try { return await operation(sftp); }
  finally { sftp.end(); }
}

function isReconnectable(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /channel open failure|open failed|not connected|no response|econnreset|econnrefused|etimedout|ehostunreach|epipe|connection (?:lost|closed)|socket.*closed|client is not connected/i.test(message);
}

function isAuthenticationFailure(error: unknown): boolean {
  const value = error as { message?: unknown; level?: unknown } | null;
  const message = typeof value?.message === "string" ? value.message : String(error);
  return value?.level === "client-authentication"
    || value?.level === "agent"
    || /authentication methods failed|authentication failure|permission denied|failed to connect to agent|failed to retrieve identities/i.test(message);
}

// ============================================================================
// File transfer helpers
//
// Three transfer directions are supported on top of the ssh2 SFTP layer:
//   · put       local (this machine)  → one or many servers
//   · get       one server            → local (this machine)
//   · transfer  one server            → one or many servers (relayed through
//                                        the local process, no extra disk)
// Directories are transferred recursively and progress is streamed through the
// tool's onUpdate callback. Large files use ssh2 fastPut/fastGet parallel
// channels, or a piping relay for server-to-server transfers.
// ============================================================================

interface TransferFile {
  /** Absolute path on the source side */
  path: string;
  /** Path relative to the copied root (used to rebuild the structure) */
  rel: string;
  size: number;
  mtimeMs: number;
}

type OverwriteMode = "always" | "skip" | "newer";

interface TxStats {
  files: number;
  bytes: number;
  skipped: number;
  startedAt: number;
}

const TX_DIRECTION_PHASE = {
  upload: "upload",
  download: "download",
  relay: "relay",
} as const;

type TxPhase = (typeof TX_DIRECTION_PHASE)[keyof typeof TX_DIRECTION_PHASE];

function stripTrailingSlash(value: string): string {
  if (value === "/") return "/";
  return value.replace(/\/+$/, "");
}

function posixDirname(p: string): string {
  return pathPosix.dirname(p);
}

/** Throttled progress reporter that streams text through the tool onUpdate callback. */
class TxProgress {
  private lastEmit = 0;
  constructor(
    private readonly onUpdate: ((update: { content: Array<{ type: "text"; text: string }>; details: unknown }) => void) | undefined,
    private readonly tool: string,
  ) {
  }
  private emit(text: string, force: boolean): void {
    if (!this.onUpdate) return;
    const now = Date.now();
    if (!force && now - this.lastEmit < 250) return;
    this.lastEmit = now;
    this.onUpdate({ content: [{ type: "text", text }], details: undefined });
  }
  /** Per-file progress line, e.g. `[ssh_remote_put] upload u@h:22 data.bin 12% (1.3 GB / 10.5 GB)` */
  file(phase: TxPhase, rel: string, done: number, total: number, remoteLabel?: string): void {
    const percent = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
    const where = remoteLabel ? ` ${remoteLabel}` : "";
    this.emit(`[${this.tool}] ${phase}${where} ${rel} ${percent}% (${formatSize(done)} / ${formatSize(total)})`, false);
  }
  /** Distinct message, always emitted. */
  message(text: string): void {
    this.emit(text, true);
  }
}

function sftpStatSafe(sftp: SFTPWrapper, p: string): Promise<Stats | null> {
  return new Promise((resolve) => {
    sftp.stat(stripTrailingSlash(p) || "/", (error, stats) => (error ? resolve(null) : resolve(stats)));
  });
}

function sftpReaddir(sftp: SFTPWrapper, p: string): Promise<Array<{ filename: string; attrs: Stats }>> {
  return new Promise((resolve, reject) => {
    sftp.readdir(stripTrailingSlash(p) || "/", (error, list) => (error ? reject(error) : resolve(list)));
  });
}

/** Recursive mkdir -p over SFTP; ignores "already exists" races. */
async function sftpEnsureDir(sftp: SFTPWrapper, dir: string): Promise<void> {
  const clean = stripTrailingSlash(dir.replace(/\\/g, "/")) || "/";
  if (clean === "/" || clean === ".") return;
  const parts = clean.split("/").filter((part) => part && part !== "." && part !== "..");
  let current = clean.startsWith("/") ? "/" : "";
  for (const part of parts) {
    current = current === "/" ? `/${part}` : current ? `${current}/${part}` : part;
    if (await sftpStatSafe(sftp, current)) continue;
    try {
      await new Promise<void>((resolve, reject) =>
        sftp.mkdir(current, (error) => (error ? reject(error) : resolve())));
    } catch (error) {
      if (await sftpStatSafe(sftp, current)) continue;
      throw error instanceof Error ? error : new Error(String(error));
    }
  }
}

/** Walk a remote directory tree, returning files with structure-preserving rel paths. */
async function collectRemoteFiles(sftp: SFTPWrapper, root: string): Promise<{ files: TransferFile[]; rootName: string; isFile: boolean }> {
  const rootStat = await sftpStatSafe(sftp, root);
  if (!rootStat) throw new Error(`Remote path does not exist: ${root}`);
  if (rootStat.isFile()) {
    const rootName = pathPosix.basename(root);
    return { files: [{ path: root, rel: rootName, size: rootStat.size ?? 0, mtimeMs: (rootStat.mtime ?? 0) * 1000 }], rootName, isFile: true };
  }
  const files: TransferFile[] = [];
  const walk = async (dir: string, relPrefix: string): Promise<void> => {
    const entries = await sftpReaddir(sftp, dir);
    for (const entry of entries) {
      if (entry.filename === "." || entry.filename === "..") continue;
      const abs = `${dir === "/" ? "" : dir}/${entry.filename}`;
      const rel = relPrefix ? `${relPrefix}/${entry.filename}` : entry.filename;
      if (entry.attrs.isDirectory()) await walk(abs, rel);
      else if (entry.attrs.isFile()) {
        files.push({ path: abs, rel, size: entry.attrs.size ?? 0, mtimeMs: (entry.attrs.mtime ?? 0) * 1000 });
      }
      // symlinks are skipped to avoid escaping the copied tree
    }
  };
  await walk(root, "");
  return { files, rootName: pathPosix.basename(root), isFile: false };
}

/** Walk a local directory tree, returning files with structure-preserving rel paths. */
async function collectLocalFiles(localAbs: string): Promise<{ files: TransferFile[]; rootName: string; isFile: boolean }> {
  const rootStat = await fsPromises.stat(localAbs);
  if (!rootStat.isDirectory()) {
    return {
      files: [{ path: localAbs, rel: basename(localAbs), size: rootStat.size, mtimeMs: rootStat.mtimeMs }],
      rootName: basename(localAbs),
      isFile: true,
    };
  }
  const files: TransferFile[] = [];
  const walk = async (dir: string, relPrefix: string): Promise<void> => {
    const entries = await fsPromises.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(abs, rel);
      else if (entry.isFile()) {
        const st = await fsPromises.stat(abs);
        files.push({ path: abs, rel, size: st.size, mtimeMs: st.mtimeMs });
      }
    }
  };
  await walk(localAbs, "");
  return { files, rootName: basename(localAbs), isFile: false };
}

function overwriteDecision(overwrite: OverwriteMode, srcMtimeMs: number, dst: { mtime?: number | Date } | null): boolean {
  if (!dst) return true;
  if (overwrite === "skip") return false;
  const dstMtime = typeof dst.mtime === "number" ? dst.mtime : dst.mtime ? dst.mtime.getTime() : 0;
  if (overwrite === "newer") return srcMtimeMs > dstMtime;
  return true;
}

/** Local destination file path for a rel path placed under a local dir. */
function localDestFile(localDir: string, rel: string): string {
  return join(localDir, ...rel.split("/"));
}

/** Remote destination file path for a rel path placed under a remote dir. */
function remoteDestFile(remoteDir: string, rel: string): string {
  return `${stripTrailingSlash(remoteDir)}/${rel}`;
}

function sftpFastPut(
  sftp: SFTPWrapper,
  localPath: string,
  remotePath: string,
  size: number,
  opts: { concurrency: number; chunkSize: number },
  onStep: (done: number, total: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.fastPut(localPath, remotePath, {
      concurrency: opts.concurrency,
      chunkSize: opts.chunkSize,
      fileSize: size,
      step: (transferred) => onStep(transferred, size),
    }, (error) => (error ? reject(error) : resolve()));
  });
}

function sftpFastGet(
  sftp: SFTPWrapper,
  remotePath: string,
  localPath: string,
  size: number,
  opts: { concurrency: number; chunkSize: number },
  onStep: (done: number, total: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.fastGet(remotePath, localPath, {
      concurrency: opts.concurrency,
      chunkSize: opts.chunkSize,
      fileSize: size,
      step: (transferred) => onStep(transferred, size),
    }, (error) => (error ? reject(error) : resolve()));
  });
}

/**
 * Relay a single file between two servers through this process using piping.
 * Memory stays bounded (backpressure through the pipe); no local disk used.
 */
async function streamRelayFile(
  srcSftp: SFTPWrapper,
  srcPath: string,
  dstSftp: SFTPWrapper,
  dstPath: string,
  onData: (bytes: number) => void,
): Promise<void> {
  const readStream = srcSftp.createReadStream(srcPath, { highWaterMark: 1024 * 1024 });
  const writeStream = dstSftp.createWriteStream(dstPath, { highWaterMark: 1024 * 1024 });
  readStream.on("data", (chunk: Buffer) => onData(chunk.length));
  await pipeline(readStream, writeStream);
}

/**
 * Relay a single file between two servers by staging on local disk first.
 * Uses the (faster) parallel fastGet/fastPut channels on both legs; needs
 * local free disk up to the file size.
 */
async function stageRelayFile(
  srcSftp: SFTPWrapper,
  srcPath: string,
  dstSftp: SFTPWrapper,
  dstPath: string,
  size: number,
  tmpDir: string,
  opts: { concurrency: number; chunkSize: number },
  onDownload: (done: number, total: number) => void,
  onUpload: (done: number, total: number) => void,
): Promise<void> {
  const tmpFile = join(tmpDir, `pi-rx-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  try {
    await sftpFastGet(srcSftp, srcPath, tmpFile, size, opts, onDownload);
    await sftpFastPut(dstSftp, tmpFile, dstPath, size, opts, onUpload);
  } finally {
    await fsPromises.unlink(tmpFile).catch(() => {});
  }
}

class PasswordInput implements Component, Focusable {
  focused = false;
  private value = "";
  constructor(
    private readonly prompt: string,
    private readonly done: (value: string | null) => void,
    private readonly renderNow: () => void,
  ) {}
  handleInput(data: string): void {
    if (matchesKey(data, Key.enter)) return this.done(this.value);
    if (matchesKey(data, Key.escape)) return this.done(null);
    if (matchesKey(data, Key.backspace)) this.value = [...this.value].slice(0, -1).join("");
    else if (matchesKey(data, Key.ctrl("u"))) this.value = "";
    else {
      const clean = data.replace(/\x1b\[200~/g, "").replace(/\x1b\[201~/g, "");
      if ([...clean].every((ch) => ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) !== 127)) this.value += clean;
    }
    this.renderNow();
  }
  render(width: number): string[] {
    return [truncateToWidth(`${this.prompt} ${"•".repeat([...this.value].length)}${this.focused ? CURSOR_MARKER : ""}\x1b[7m \x1b[27m`, width, "")];
  }
  invalidate(): void {}
}

/**
 * pi's interactive host renders exactly one extension dialog at a time: a second
 * `ctx.ui.custom`/`ctx.ui.confirm` swaps the component out of the editor area
 * without resolving the earlier promise, so that caller waits forever. The agent
 * routinely opens several endpoints in one turn, which used to leave every
 * connection after the first hanging on a prompt that could never be answered.
 * All connect-time prompts therefore queue here instead of racing for the slot.
 */
let uiDialogQueue: Promise<unknown> = Promise.resolve();
let pendingUiDialogs = 0;

/** Prompt slots currently executing or waiting (one per pending connect). */
export function pendingUiDialogCount(): number {
  return pendingUiDialogs;
}

/** Run one interactive dialog once every earlier dialog has been answered. */
export function withUiDialog<T>(run: () => Promise<T>): Promise<T> {
  pendingUiDialogs += 1;
  // The counter is decremented inside the queue chain, before the next queued
  // dialog starts, so a prompt never reports itself as still waiting.
  const settled = uiDialogQueue.then(run, run).then(
    (value) => { pendingUiDialogs -= 1; return value; },
    (error) => { pendingUiDialogs -= 1; throw error; },
  );
  uiDialogQueue = settled.catch(() => {});
  return settled;
}

/**
 * Drop a queue that can never drain, e.g. a dialog pi closed without resolving
 * while reloading the extension. Otherwise every later prompt would wait on it.
 */
export function resetUiDialogQueue(): void {
  uiDialogQueue = Promise.resolve();
  pendingUiDialogs = 0;
}

/**
 * Prompt text for one SSH password. The endpoint label (`user@host:port`) is the
 * first thing in the line so a burst of parallel connections still tells you
 * which server each prompt belongs to.
 */
export function passwordPromptText(label: string, hint?: string, waiting = 0): string {
  const detail = [hint, waiting > 0 ? `${waiting} more waiting` : undefined].filter(Boolean).join(" · ");
  return `SSH password for ${label}${detail ? ` (${detail})` : ""} — Enter submits, Esc skips:`;
}

async function askPassword(ctx: any, label: string, hint?: string): Promise<string | null> {
  return withUiDialog(async () => {
    // Inside the queue this prompt already counts itself; the rest are behind it.
    const prompt = passwordPromptText(label, hint, pendingUiDialogs - 1);
    if (ctx.mode !== "tui") return (await ctx.ui.input(prompt, "password")) ?? null;
    return ctx.ui.custom((tui: any, _theme: any, _keys: any, done: (value: string | null) => void) =>
      new PasswordInput(prompt, done, () => tui.requestRender()));
  });
}

export default function sshRemoteExtension(pi: ExtensionAPI) {
  const localCwd = process.cwd();
  let remote: RemoteState | null = null;
  let routeRemoteTools = false;
  let currentCtx: any;
  const connections = new Map<string, RemoteState>();
  const reconnectPromises = new Map<string, Promise<RemoteState>>();
  const forwardServers = new Map<number, Server>();
  let lastConnectionError: string | undefined;
  let lastCommand = credentialCache.resume?.command ?? activeSshCommand() ?? "";
  const REMOTE_ABSOLUTE_MARKER = "__pi_ssh_remote_absolute__";
  const REMOTE_HOME_MARKER = "__pi_ssh_remote_home__";

  const configuredCwd = (command: string): string =>
    endpointConfig(loadRemoteConfig(), command).remoteCwd || FALLBACK_REMOTE_CWD;

  const configuredForwards = (command: string): string[] =>
    endpointConfig(loadRemoteConfig(), command).forwards ?? [];

  const prepareRemoteToolPath = (path: string): string => {
    const normalized = path.replace(/\\/g, "/");
    if (normalized === "~" || normalized.startsWith("~/")) {
      return join(localCwd, REMOTE_HOME_MARKER, ...normalized.replace(/^~\/?/, "").split("/").filter(Boolean));
    }
    if (normalized.startsWith("/")) {
      return join(localCwd, REMOTE_ABSOLUTE_MARKER, ...normalized.slice(1).split("/").filter(Boolean));
    }
    return path;
  };

  const mapPath = (state: RemoteState, path: string): string => {
    if (path === localCwd) return state.cwd;
    const prefix = localCwd.endsWith(sep) ? localCwd : localCwd + sep;
    if (path.startsWith(prefix)) {
      const suffix = relative(localCwd, path).split(sep).join("/");
      if (suffix === REMOTE_ABSOLUTE_MARKER) return "/";
      if (suffix.startsWith(`${REMOTE_ABSOLUTE_MARKER}/`)) return "/" + suffix.slice(REMOTE_ABSOLUTE_MARKER.length + 1);
      if (suffix === REMOTE_HOME_MARKER) return state.home;
      if (suffix.startsWith(`${REMOTE_HOME_MARKER}/`)) return state.home.replace(/\/$/, "") + "/" + suffix.slice(REMOTE_HOME_MARKER.length + 1);
      return state.cwd.replace(/\/$/, "") + "/" + suffix;
    }
    return path;
  };

  const resolveEndpointKey = (selector?: string, connectedOnly = false): string => {
    const config = loadRemoteConfig();
    const keys = connectedOnly ? [...connections.keys()] : Object.keys(config.endpoints ?? {});
    const requested = selector?.trim();
    if (!requested) {
      const activeKey = remote ? cacheId(remote) : config.activeEndpoint;
      if (activeKey && (!connectedOnly || connections.has(activeKey))) return activeKey;
      if (keys.length === 1) return keys[0]!;
      throw new Error(connectedOnly ? "No active SSH connection" : "No SSH endpoint selected");
    }
    const matches = endpointSelectorMatches(keys, config.endpoints ?? {}, requested);
    if (matches.length !== 1) {
      // List every configured endpoint (not only connected ones) so the model can
      // correct itself on the next call instead of guessing an address again.
      throw new Error(describeEndpointResolutionFailure(
        requested,
        Object.keys(config.endpoints ?? {}),
        config.endpoints ?? {},
        new Set(connections.keys()),
        connectedOnly,
        matches,
      ));
    }
    return matches[0]!;
  };

  /** Endpoints currently dialing: probing the host key, authenticating, or waiting for a password. */
  const connectingLabels = new Set<string>();

  const status = (ctx: any) => {
    currentCtx = ctx;
    const count = connections.size;
    const connecting = [...connectingLabels];
    if (connecting.length) {
      const shown = connecting.length > 3 ? `${connecting.slice(0, 3).join(", ")}, +${connecting.length - 3}` : connecting.join(", ");
      ctx.ui.setStatus("ssh-remote", ctx.ui.theme.fg("warning", `SSH connecting ${shown}…${count ? ` · ${count} connected` : ""}`));
    } else if (!remote) {
      ctx.ui.setStatus("ssh-remote", count ? ctx.ui.theme.fg("accent", `SSH ${count} connected · tools local`) : undefined);
    } else if (routeRemoteTools) {
      ctx.ui.setStatus("ssh-remote", ctx.ui.theme.fg("accent", `SSH ${count} connected · active ${endpointDisplayLabel(remote)}:${remote.cwd}`));
    } else {
      ctx.ui.setStatus("ssh-remote", ctx.ui.theme.fg("accent", `SSH ${count} connected · selected ${endpointDisplayLabel(remote)} · tools local${forwardServers.size ? ` · tunnels ${[...forwardServers.keys()].join(",")}` : ""}`));
    }
  };

  const connectionSnapshot = () => {
    const config = loadRemoteConfig();
    return [...connections.entries()].map(([endpoint, state]) => ({
      endpoint,
      cwd: state.cwd,
      note: config.endpoints?.[endpoint]?.note,
      selected: Boolean(remote && cacheId(remote) === endpoint),
      passwordSaved: persistentCredentials.has(endpoint),
    }));
  };

  const attachClient = (state: RemoteState) => {
    const { client } = state;
    const endpointKey = cacheId(state);
    client.on("close", () => {
      if (connections.get(endpointKey)?.client !== client) return;
      if (remote?.client !== client) {
        connections.delete(endpointKey);
        if (currentCtx) status(currentCtx);
        return;
      }
      if (currentCtx) currentCtx.ui.setStatus("ssh-remote", currentCtx.ui.theme.fg("warning", `SSH remote reconnecting ${endpointDisplayLabel(state)}…`));
      void reconnectEndpoint(endpointKey).catch((error) => {
        connections.delete(endpointKey);
        if (remote?.client === client) remote = null;
        if (currentCtx) {
          status(currentCtx);
          currentCtx.ui.notify(`SSH remote automatic reconnection failed (${endpointKey}): ${(error as Error).message}`, "error");
        }
      });
    });
  };

  const establish = async (parsed: ParsedSsh, password: string | undefined, cwd: string): Promise<RemoteState> => {
    const key = `${parsed.host}:${parsed.port}`;
    const fingerprint = loadKnownHosts()[key];
    if (!fingerprint) throw new Error(`Host ${key} is not trusted; connect interactively with /remote first`);
    const client = await connect(parsed, password, fingerprint);
    try {
      const cdCommand = cwd === FALLBACK_REMOTE_CWD ? "cd -- ~" : `cd -- ${quote(cwd)}`;
      const resolved = (await execRemote(client, `${cdCommand} && printf '%s\\n' "$HOME" && pwd -P`)).toString().trim().split("\n");
      const home = resolved.shift()?.trim();
      const resolvedCwd = resolved.join("\n").trim();
      if (!home || !resolvedCwd) throw new Error("Unable to resolve remote HOME or working directory");
      const state: RemoteState = { ...parsed, client, cwd: resolvedCwd, home };
      attachClient(state);
      return state;
    } catch (error) {
      client.end();
      throw error;
    }
  };

  async function reconnectEndpoint(endpointKey: string): Promise<RemoteState> {
    const pending = reconnectPromises.get(endpointKey);
    if (pending) return pending;
    const current = connections.get(endpointKey);
    const config = loadRemoteConfig();
    const saved = config.endpoints?.[endpointKey];
    const resume = credentialCache.resume && cacheId(parseSshCommand(credentialCache.resume.command)) === endpointKey
      ? credentialCache.resume
      : undefined;
    const command = current?.command ?? resume?.command ?? saved?.sshCommand;
    const cwd = current?.cwd ?? resume?.cwd ?? saved?.remoteCwd ?? FALLBACK_REMOTE_CWD;
    if (!command) throw new Error(`No SSH endpoint configuration for ${endpointKey}`);
    const parsed = parseSshCommand(command);
    const password = await getCachedPassword(parsed);
    const reconnecting = (async () => {
      const oldClient = current?.client;
      let next: RemoteState;
      try {
        next = await establish(parsed, password, cwd);
      } catch (error) {
        if (password && isAuthenticationFailure(error)) deleteCachedPassword(parsed);
        throw error;
      }
      connections.set(endpointKey, next);
      if (remote && cacheId(remote) === endpointKey) {
        remote = next;
        credentialCache.resume = { command: parsed.command, cwd: next.cwd };
      }
      oldClient?.end();
      if (currentCtx) status(currentCtx);
      return next;
    })().finally(() => reconnectPromises.delete(endpointKey));
    reconnectPromises.set(endpointKey, reconnecting);
    return reconnecting;
  }

  const reconnectRemote = async (): Promise<RemoteState> => {
    const endpointKey = remote
      ? cacheId(remote)
      : credentialCache.resume
        ? cacheId(parseSshCommand(credentialCache.resume.command))
        : resolveEndpointKey(undefined);
    return reconnectEndpoint(endpointKey);
  };

  const withReconnectFor = async <T>(endpointKey: string, operation: (client: Client) => Promise<T>): Promise<T> => {
    const state = connections.get(endpointKey);
    if (!state) throw new Error(`SSH endpoint is not connected: ${endpointKey}`);
    try { return await operation(state.client); }
    catch (error) {
      if (!isReconnectable(error)) throw error;
      const reconnected = await reconnectEndpoint(endpointKey);
      return operation(reconnected.client);
    }
  };

  const withReconnect = async <T>(operation: (client: Client) => Promise<T>): Promise<T> => {
    if (!remote) throw new Error("SSH remote is not connected");
    return withReconnectFor(cacheId(remote), operation);
  };

  const changeRemoteCwd = async (requested: string, ctx: any, state = remote): Promise<string> => {
    if (!state) throw new Error("SSH remote is not connected");
    const target = requested.trim() || FALLBACK_REMOTE_CWD;
    const targetCommand = target === FALLBACK_REMOTE_CWD ? "cd -- ~" : `cd -- ${quote(target)}`;
    const endpointKey = cacheId(state);
    const resolved = (await withReconnectFor(endpointKey, (client) => execRemote(
      client,
      `cd -- ${quote(state.cwd)} && ${targetCommand} && pwd -P`,
    ))).toString().trim();
    const current = connections.get(endpointKey);
    if (current) current.cwd = resolved;
    state.cwd = resolved;
    const isActive = Boolean(remote && cacheId(remote) === endpointKey);
    if (isActive) credentialCache.resume = { command: state.command, cwd: resolved };
    saveEndpointConfig(state.command, { remoteCwd: resolved }, isActive);
    status(ctx);
    return resolved;
  };

  const standaloneCdTarget = (command: string): string | undefined => {
    try {
      const words = shellWords(command);
      if (words[0] !== "cd" || words.length > 3) return undefined;
      if (words.length === 3 && words[1] !== "--") return undefined;
      return words.at(-1) === "cd" || words.at(-1) === "--" ? FALLBACK_REMOTE_CWD : words.at(-1);
    } catch {
      return undefined;
    }
  };

  /**
   * One dial-in-progress per endpoint, shared by every caller that asks for that
   * endpoint while it is still connecting. Without it the agent opening the same
   * host from several parallel tool calls would dial twice, prompt twice, and
   * race two clients into `connections`.
   */
  const pendingConnects = new Map<string, Promise<RemoteState | null>>();

  const connectInteractive = async (command: string, ctx: any, cwd?: string, activate = false): Promise<RemoteState | null> => {
    let parsed: ParsedSsh;
    try { parsed = parseSshCommand(command); }
    catch (error) {
      lastConnectionError = (error as Error).message;
      ctx.ui.notify(lastConnectionError, "error");
      return null;
    }
    lastConnectionError = undefined;
    const endpointKey = cacheId(parsed);

    const inFlight = pendingConnects.get(endpointKey);
    if (inFlight) {
      const shared = await inFlight;
      if (shared && activate && remote !== shared) {
        remote = shared;
        credentialCache.resume = { command: shared.command, cwd: shared.cwd };
        lastCommand = shared.command;
        saveEndpointConfig(shared.command, { remoteCwd: shared.cwd }, true);
        status(ctx);
      }
      return shared;
    }

    const attempt = connectParsed(parsed, command, ctx, cwd, activate)
      .finally(() => { if (pendingConnects.get(endpointKey) === attempt) pendingConnects.delete(endpointKey); });
    pendingConnects.set(endpointKey, attempt);
    return attempt;
  };

  const connectParsed = async (parsed: ParsedSsh, command: string, ctx: any, cwd?: string, activate = false): Promise<RemoteState | null> => {
    const endpointKey = cacheId(parsed);
    const existing = connections.get(endpointKey);
    if (existing) {
      const select = activate || !remote;
      if (select) {
        remote = existing;
        credentialCache.resume = { command: existing.command, cwd: existing.cwd };
        lastCommand = existing.command;
        saveEndpointConfig(existing.command, { remoteCwd: existing.cwd }, true);
      }
      status(ctx);
      ctx.ui.notify(`SSH remote already connected: ${endpointDisplayLabel(existing)}:${existing.cwd}${select ? " (selected)" : ""}`, "info");
      return existing;
    }

    const label = endpointDisplayLabel(parsed);
    connectingLabels.add(label);
    status(ctx);
    try {
      const key = `${parsed.host}:${parsed.port}`;
      const savedFingerprint = loadKnownHosts()[key];
      const fingerprint = await probeFingerprint(parsed);
      // Host-key dialogs share the password prompt queue: two unverified hosts
      // opened in one turn must not overwrite each other's dialog.
      if (!savedFingerprint) {
        const trusted = await withUiDialog(() => Promise.resolve(ctx.ui.confirm("Trust SSH host", `${parsed.label}\nHost key: ${displayFingerprint(fingerprint)}\nTrust and save this key?`)));
        if (!trusted) { lastConnectionError = "The host key was not trusted"; return null; }
        saveKnownHost(key, fingerprint);
      } else if (savedFingerprint !== fingerprint) {
        const trusted = await withUiDialog(() => Promise.resolve(ctx.ui.confirm(
          "SSH host key changed",
          `${parsed.label}\nPrevious key: ${displayFingerprint(savedFingerprint)}\nNew key: ${displayFingerprint(fingerprint)}\nVerify the server identity. Update the saved key and continue?`,
        )));
        if (!trusted) { lastConnectionError = "The changed host key was rejected"; return null; }
        saveKnownHost(key, fingerprint);
      }

      let password = await getCachedPassword(parsed);
      let passwordWasPrompted = false;
      let next: RemoteState;
      try {
        next = await establish(parsed, password, cwd ?? configuredCwd(command));
      } catch (error) {
        if (!isAuthenticationFailure(error)) throw error;
        const hadSavedPassword = password !== undefined;
        if (hadSavedPassword) deleteCachedPassword(parsed);
        password = await askPassword(ctx, label, hadSavedPassword ? "saved password rejected" : "no saved password") ?? undefined;
        if (!password) {
          lastConnectionError = "SSH authentication failed and no replacement password was provided";
          return null;
        }
        passwordWasPrompted = true;
        next = await establish(parsed, password, cwd ?? configuredCwd(command));
      }
      connections.set(endpointKey, next);
      if (passwordWasPrompted && password) {
        const persistence = await setCachedPassword(parsed, password);
        if (!persistence.persisted) {
          ctx.ui.notify(`SSH connected, but the password could not be saved (${persistence.error || "no credential backend available"}); it stays in this Pi process only.`, "warning");
        }
      }
      // Selection is decided once the dial is done: when several first-time
      // connections run in parallel, the first one to finish becomes active
      // instead of the last one started stealing the selection.
      const shouldSelect = activate || !remote;
      if (shouldSelect) {
        remote = next;
        credentialCache.resume = { command, cwd: next.cwd };
        lastCommand = command;
      }
      lastConnectionError = undefined;
      saveEndpointConfig(command, { remoteCwd: next.cwd }, shouldSelect);
      ctx.ui.notify(`SSH remote connected: ${endpointDisplayLabel(next)}:${next.cwd}${shouldSelect ? " (selected)" : ""}; built-in tools remain ${routeRemoteTools ? "remote-routed" : "local"}`, "info");
      return next;
    } catch (error) {
      if (isAuthenticationFailure(error)) deleteCachedPassword(parsed);
      lastConnectionError = (error as Error).message;
      ctx.ui.notify(`SSH remote connection failed: ${lastConnectionError}`, "error");
      return null;
    } finally {
      connectingLabels.delete(label);
      status(ctx);
    }
  };

  const ensureConnected = async (ctx: any, selector?: string, activate = false): Promise<RemoteState> => {
    if (!selector && remote) return remote;
    if (selector) {
      const endpointKey = resolveEndpointKey(selector);
      const connected = connections.get(endpointKey);
      if (connected) return connected;
      const command = loadRemoteConfig().endpoints?.[endpointKey]?.sshCommand;
      if (!command) throw new Error(`Endpoint has no SSH command: ${endpointKey}`);
      const state = await connectInteractive(command, ctx, configuredCwd(command), activate);
      if (!state) throw new Error(`SSH connection was cancelled or failed: ${endpointKey}`);
      return state;
    }
    if (credentialCache.resume) {
      const endpointKey = cacheId(parseSshCommand(credentialCache.resume.command));
      const state = await reconnectEndpoint(endpointKey);
      remote = state;
      connections.set(endpointKey, state);
      return state;
    }
    const command = lastCommand || activeSshCommand();
    if (!command) throw new Error("No SSH endpoint configured; use /remote ssh USER@HOST -p PORT");
    const state = await connectInteractive(command, ctx, configuredCwd(command), activate);
    if (!state) throw new Error("SSH remote connection was cancelled or failed");
    return state;
  };

  const startForward = async (state: RemoteState, spec: ForwardSpec): Promise<void> => {
    if (forwardServers.has(spec.localPort)) return;
    const endpointKey = cacheId(state);
    const server = createServer((socket: Socket) => {
      const openForward = async () => {
        if (!connections.has(endpointKey)) await reconnectEndpoint(endpointKey);
        return withReconnectFor(endpointKey, (client) => new Promise<ClientChannel>((resolve, reject) =>
          client.forwardOut("127.0.0.1", 0, spec.remoteHost, spec.remotePort, (error, stream) =>
            error ? reject(error) : resolve(stream))));
      };
      void openForward().then((stream) => {
            socket.on("error", () => stream.close());
            stream.on("error", () => socket.destroy());
            socket.pipe(stream).pipe(socket);
          }, () => socket.destroy());
    });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => { server.close(); reject(error); };
      server.once("error", onError);
      server.listen(spec.localPort, "127.0.0.1", () => {
        server.off("error", onError);
        server.on("error", () => {});
        resolve();
      });
    });
    forwardServers.set(spec.localPort, server);
  };

  const stopForwards = async (): Promise<void> => {
    const servers = [...forwardServers.values()];
    forwardServers.clear();
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  };

  const disconnectEndpoint = (ctx: any, selector?: string, forgetPassword = false): string => {
    const endpointKey = resolveEndpointKey(selector, true);
    const previous = connections.get(endpointKey)!;
    connections.delete(endpointKey);
    reconnectPromises.delete(endpointKey);
    if (forgetPassword) deleteCachedPassword(previous);
    if (remote && cacheId(remote) === endpointKey) {
      remote = null;
      routeRemoteTools = false;
      credentialCache.resume = undefined;
      void stopForwards();
    }
    previous.client.end();
    status(ctx);
    return endpointKey;
  };

  const disconnectAll = (ctx: any, forgetPasswords = false): number => {
    const states = [...connections.values()];
    connections.clear();
    reconnectPromises.clear();
    remote = null;
    routeRemoteTools = false;
    credentialCache.resume = undefined;
    void stopForwards();
    for (const state of states) {
      if (forgetPasswords) deleteCachedPassword(state);
      state.client.end();
    }
    status(ctx);
    return states.length;
  };

  const forgetEndpoint = (ctx: any, selector?: string): string => {
    const endpointKey = resolveEndpointKey(selector, false);
    if (connections.has(endpointKey)) disconnectEndpoint(ctx, endpointKey, false);
    deleteCachedPasswordById(endpointKey);
    status(ctx);
    return endpointKey;
  };

  const forgetAllPasswords = (ctx: any): { disconnected: number; forgotten: number } => {
    const disconnected = disconnectAll(ctx, false);
    const forgotten = clearCachedPasswords();
    return { disconnected, forgotten };
  };

  const remoteReadOps = (state: RemoteState): ReadOperations => ({
    readFile: (path) => withReconnectFor(cacheId(state), (client) => withSftp(client, (sftp) =>
      new Promise<Buffer>((resolve, reject) => sftp.readFile(mapPath(state, path), (error, data) => error ? reject(error) : resolve(data))))),
    access: (path) => withReconnectFor(cacheId(state), (client) => withSftp(client, (sftp) =>
      new Promise<void>((resolve, reject) => sftp.stat(mapPath(state, path), (error) => error ? reject(error) : resolve())))),
    detectImageMimeType: async (path) => {
      try {
        const mime = (await withReconnectFor(cacheId(state), (client) => execRemote(client, `file --mime-type -b -- ${quote(mapPath(state, path))}`))).toString().trim();
        return ["image/jpeg", "image/png", "image/gif", "image/webp"].includes(mime) ? mime : null;
      } catch { return null; }
    },
  });

  const remoteWriteOps = (state: RemoteState): WriteOperations => ({
    writeFile: (path, content) => withReconnectFor(cacheId(state), (client) => withSftp(client, (sftp) =>
      new Promise<void>((resolve, reject) => sftp.writeFile(mapPath(state, path), content, (error) => error ? reject(error) : resolve())))),
    mkdir: async (path) => { await withReconnectFor(cacheId(state), (client) => execRemote(client, `mkdir -p -- ${quote(mapPath(state, path))}`)); },
  });

  const remoteEditOps = (state: RemoteState): EditOperations => {
    const read = remoteReadOps(state);
    const write = remoteWriteOps(state);
    return { readFile: read.readFile, access: read.access, writeFile: write.writeFile };
  };

  const openExecChannel = async (state: RemoteState, command: string, pty = true): Promise<ClientChannel> =>
    withReconnectFor(cacheId(state), (client) => new Promise<ClientChannel>((resolve, reject) => {
      const options: any = pty ? { pty: { term: "xterm", rows: 40, cols: 160 } } : {};
      client.exec(command, options, (error, stream) => error ? reject(error) : resolve(stream));
    }));

  const remoteBashOps = (state: RemoteState): BashOperations => ({
    exec: (command, cwd, { onData, signal, timeout }) => new Promise((resolve, reject) => {
      const timeoutSeconds = parseRemoteTimeout(timeout ?? configuredRemoteTimeout(cacheId(state)));
      const remoteCommand = withRemoteTimeout(command, timeoutSeconds);
      const full = `cd -- ${quote(mapPath(state, cwd))} && ${remoteCommand}`;
      void openExecChannel(state, full, true).then((stream) => {
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; stream.close(); }, (timeoutSeconds + 8) * 1000);
        let abortTimer: ReturnType<typeof setTimeout> | undefined;
        const abort = () => {
          try { stream.signal("INT"); } catch { /* ignore */ }
          abortTimer = setTimeout(() => stream.close(), 1200);
        };
        signal?.addEventListener("abort", abort, { once: true });
        if (signal?.aborted) abort();
        const cleanChunk = (chunk: Buffer) => onData(Buffer.from(sanitizePtyOutput(chunk.toString("utf8")), "utf8"));
        stream.on("data", cleanChunk);
        if (stream.stderr) stream.stderr.on("data", cleanChunk);
        stream.on("close", (code: number | null) => {
          clearTimeout(timer);
          if (abortTimer) clearTimeout(abortTimer);
          signal?.removeEventListener("abort", abort);
          if (signal?.aborted) reject(new Error("aborted"));
          else if (timedOut || code === 124 || code === 137) reject(new Error(`timeout:${timeoutSeconds}`));
          else resolve({ exitCode: code });
        });
      }, reject);
    }),
  });

  // ---- file-transfer closure helpers ----------------------------------------

  /** Resolve a remote path: `~` → home, absolute → verbatim, marker-style → mapped, else relative to cwd. */
  const resolveRemotePath = (state: RemoteState, p: string): string => {
    const normalized = p.replace(/\\/g, "/").trim();
    if (!normalized) throw new Error("Empty remote path");
    if (normalized === "~") return state.home;
    if (normalized.startsWith("~/")) return `${state.home}/${normalized.slice(2)}`;
    if (normalized.startsWith("/")) return normalized;
    const localPrefix = localCwd.endsWith(sep) ? localCwd : localCwd + sep;
    if (normalized.startsWith(localPrefix) && normalized.includes("__pi_ssh_remote_")) return mapPath(state, normalized);
    return `${state.cwd.replace(/\/$/, "")}/${normalized}`;
  };

  /** Resolve a local path; relative paths are anchored to the local process cwd. */
  const resolveLocalPath = (p: string): string => {
    const normalized = p.trim();
    if (!normalized) throw new Error("Empty local path");
    return isLocalAbsolute(normalized) ? normalized : join(localCwd, normalized);
  };

  /** Expand single/targets selectors into one state per unique connected endpoint. */
  const resolveTargetStates = async (ctx: any, endpoint?: string, targets?: string[]): Promise<RemoteState[]> => {
    const selectors: string[] = [];
    if (endpoint) selectors.push(endpoint);
    if (targets?.length) selectors.push(...targets);
    if (!selectors.length) throw new Error("Specify a single endpoint or a targets list of endpoints");
    const states: RemoteState[] = [];
    const seen = new Set<string>();
    for (const selector of selectors) {
      const state = await ensureConnected(ctx, selector, false);
      const key = cacheId(state);
      if (!seen.has(key)) {
        seen.add(key);
        states.push(state);
      }
    }
    return states;
  };

  /** Bounded-parallel execution across a list of states. */
  const runFanOut = async <T>(states: RemoteState[], worker: (state: RemoteState, index: number) => Promise<T>, concurrency: number): Promise<T[]> => {
    const results = new Array<T>(states.length);
    let cursor = 0;
    const workerCount = Math.min(concurrency, states.length);
    await Promise.all(Array.from({ length: workerCount }, async () => {
      while (cursor < states.length) {
        const index = cursor++;
        results[index] = await worker(states[index]!, index);
      }
    }));
    return results;
  };

  // ---- password decoding ----------------------------------------------------

  /**
   * Resolve the plaintext password for an endpoint from the in-memory cache
   * first, then from the persisted credential store (Windows DPAPI, macOS
   * Keychain, libsecret, or the local encrypted key file). Does not
   * require the endpoint to be currently connected.
   */
  const getDecodedPassword = async (selector?: string): Promise<{ endpoint: string; password: string; source: "memory" | "persisted" }> => {
    const endpointKey = resolveEndpointKey(selector, false);
    const memory = credentialCache.passwords.get(endpointKey);
    if (memory !== undefined) return { endpoint: endpointKey, password: memory, source: "memory" };
    const saved = await persistentCredentials.get(endpointKey);
    if (saved) {
      credentialCache.passwords.set(endpointKey, saved);
      return { endpoint: endpointKey, password: saved, source: "persisted" };
    }
    throw new Error(
      `No saved password for SSH endpoint ${endpointKey}. Connect to it at least once (ssh_remote_control connect / /remote ssh) so the password is saved with ${persistentCredentials.label}, then decode it again.`,
    );
  };

  // ---- local → remote (put) ------------------------------------------------

  const putToState = async (
    state: RemoteState,
    localAbs: string,
    remoteTarget: string,
    opts: { overwrite: OverwriteMode; concurrency: number; chunkSize: number; recursive: boolean },
    progress: TxProgress,
    signal?: AbortSignal,
  ): Promise<TxStats> => {
    const stats: TxStats = { files: 0, bytes: 0, skipped: 0, startedAt: Date.now() };
    await withReconnectFor(cacheId(state), (client) => withSftp(client, async (sftp) => {
      const collected = await collectLocalFiles(localAbs);
      if (!opts.recursive && !collected.isFile) throw new Error("Source is a directory; set recursive=true to transfer it");
      const { remoteDir, exactDest } = await (async (): Promise<{ remoteDir: string; exactDest?: string }> => {
        if (!collected.isFile) return { remoteDir: stripTrailingSlash(remoteTarget) || "/" };
        if (/[\\/]$/.test(remoteTarget)) return { remoteDir: stripTrailingSlash(remoteTarget) };
        const existing = await sftpStatSafe(sftp, remoteTarget);
        if (existing?.isDirectory()) return { remoteDir: stripTrailingSlash(remoteTarget) };
        return { remoteDir: posixDirname(remoteTarget), exactDest: remoteTarget };
      })();
      await sftpEnsureDir(sftp, remoteDir);
      for (const file of collected.files) {
        if (signal?.aborted) throw new Error("Transfer aborted");
        const dst = exactDest ?? remoteDestFile(remoteDir, file.rel);
        const dstStat = await sftpStatSafe(sftp, dst);
        if (!overwriteDecision(opts.overwrite, file.mtimeMs, dstStat)) {
          stats.skipped += 1;
          continue;
        }
        await sftpEnsureDir(sftp, posixDirname(dst));
        await sftpFastPut(sftp, file.path, dst, file.size, { concurrency: opts.concurrency, chunkSize: opts.chunkSize },
          (done, total) => progress.file(TX_DIRECTION_PHASE.upload, file.rel, done, total, cacheId(state)));
        stats.files += 1;
        stats.bytes += file.size;
      }
    }));
    return stats;
  };

  // ---- remote → local (get) ------------------------------------------------

  const getFromState = async (
    state: RemoteState,
    remoteSource: string,
    localTarget: string,
    opts: { overwrite: OverwriteMode; concurrency: number; chunkSize: number; recursive: boolean },
    progress: TxProgress,
    signal?: AbortSignal,
  ): Promise<TxStats> => {
    const stats: TxStats = { files: 0, bytes: 0, skipped: 0, startedAt: Date.now() };
    await withReconnectFor(cacheId(state), (client) => withSftp(client, async (sftp) => {
      const collected = await collectRemoteFiles(sftp, remoteSource);
      if (!opts.recursive && !collected.isFile) throw new Error("Source is a directory; set recursive=true to transfer it");
      const isSingleFile = collected.files.length === 1 && collected.files[0]!.rel === collected.rootName;
      const { localDir, exactDest } = await (async (): Promise<{ localDir: string; exactDest?: string }> => {
        if (!isSingleFile) return { localDir: localTarget };
        if (/[\\/]$/.test(localTarget)) return { localDir: stripTrailingSlash(localTarget) };
        try {
          return (await fsPromises.stat(resolveLocal(localTarget))).isDirectory()
            ? { localDir: stripTrailingSlash(localTarget) }
            : { localDir: dirname(localTarget), exactDest: resolveLocal(localTarget) };
        } catch {
          return { localDir: dirname(localTarget), exactDest: resolveLocal(localTarget) };
        }
      })();
      await fsPromises.mkdir(localDir, { recursive: true });
      for (const file of collected.files) {
        if (signal?.aborted) throw new Error("Transfer aborted");
        const dst = exactDest ?? localDestFile(localDir, file.rel);
        let dstStat: { mtime?: number | Date } | null = null;
        try { dstStat = await fsPromises.stat(dst); } catch { /* missing is fine */ }
        if (!overwriteDecision(opts.overwrite, file.mtimeMs, dstStat)) {
          stats.skipped += 1;
          continue;
        }
        await fsPromises.mkdir(dirname(dst), { recursive: true });
        await sftpFastGet(sftp, file.path, dst, file.size, { concurrency: opts.concurrency, chunkSize: opts.chunkSize },
          (done, total) => progress.file(TX_DIRECTION_PHASE.download, file.rel, done, total, cacheId(state)));
        stats.files += 1;
        stats.bytes += file.size;
      }
    }));
    return stats;
  };

  // ---- remote → remote(s) (transfer, relayed through local process) --------

  const transferToState = async (
    srcState: RemoteState,
    srcPath: string,
    dstState: RemoteState,
    dstTarget: string,
    opts: { overwrite: OverwriteMode; concurrency: number; chunkSize: number; via: "stream" | "stage"; recursive: boolean },
    progress: TxProgress,
    signal?: AbortSignal,
  ): Promise<TxStats> => {
    const stats: TxStats = { files: 0, bytes: 0, skipped: 0, startedAt: Date.now() };
    await withReconnectFor(cacheId(srcState), (client) => withSftp(client, async (srcSftp) => {
      const collected = await collectRemoteFiles(srcSftp, srcPath);
      if (!opts.recursive && !collected.isFile) throw new Error("Source is a directory; set recursive=true to transfer it");
      const tmpDir = opts.via === "stage" ? mkdtempSync(join(tmpdir(), "pi-rx-stage-")) : undefined;
      await withReconnectFor(cacheId(dstState), (dstClient) => withSftp(dstClient, async (dstSftp) => {
        const { remoteDir, exactDest } = await (async (): Promise<{ remoteDir: string; exactDest?: string }> => {
          const single = collected.files.length === 1 && collected.files[0]!.rel === collected.rootName;
          if (!single) return { remoteDir: stripTrailingSlash(dstTarget) || "/" };
          if (/[\\/]$/.test(dstTarget)) return { remoteDir: stripTrailingSlash(dstTarget) };
          const existing = await sftpStatSafe(dstSftp, dstTarget);
          if (existing?.isDirectory()) return { remoteDir: stripTrailingSlash(dstTarget) };
          return { remoteDir: posixDirname(dstTarget), exactDest: dstTarget };
        })();
        await sftpEnsureDir(dstSftp, remoteDir);
        for (const file of collected.files) {
          if (signal?.aborted) throw new Error("Transfer aborted");
          const dst = exactDest ?? remoteDestFile(remoteDir, file.rel);
          const dstStat = await sftpStatSafe(dstSftp, dst);
          if (!overwriteDecision(opts.overwrite, file.mtimeMs, dstStat)) {
            stats.skipped += 1;
            continue;
          }
          await sftpEnsureDir(dstSftp, posixDirname(dst));
          if (opts.via === "stage") {
            await stageRelayFile(
              srcSftp, file.path, dstSftp, dst, file.size, tmpDir!,
              { concurrency: opts.concurrency, chunkSize: opts.chunkSize },
              (done, total) => progress.file(TX_DIRECTION_PHASE.download, file.rel, done, total, cacheId(srcState)),
              (done, total) => progress.file(TX_DIRECTION_PHASE.upload, file.rel, done, total, cacheId(dstState)),
            );
          } else {
            let relayed = 0;
            await streamRelayFile(srcSftp, file.path, dstSftp, dst, (bytes) => {
              relayed += bytes;
              progress.file(TX_DIRECTION_PHASE.relay, file.rel, relayed, file.size, cacheId(dstState));
            });
          }
          stats.files += 1;
          stats.bytes += file.size;
        }
      }));
      if (tmpDir) fsPromises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }));
    return stats;
  };

  const localRead = createReadTool(localCwd);
  const localWrite = createWriteTool(localCwd);
  const localEdit = createEditTool(localCwd);
  const localBash = createBashTool(localCwd);
  const { prepareArguments: _readPrepareArguments, ...remoteReadBase } = localRead;
  const { prepareArguments: _writePrepareArguments, ...remoteWriteBase } = localWrite;
  const { prepareArguments: _editPrepareArguments, ...remoteEditBase } = localEdit;
  pi.registerTool({ ...localRead, execute: (id, params, signal, update) => { const state = remote; return state && routeRemoteTools ? createReadTool(localCwd, { operations: remoteReadOps(state) }).execute(id, { ...params, path: prepareRemoteToolPath(params.path) }, signal, update) : localRead.execute(id, params, signal, update); } });
  pi.registerTool({ ...localWrite, execute: (id, params, signal, update) => { const state = remote; return state && routeRemoteTools ? createWriteTool(localCwd, { operations: remoteWriteOps(state) }).execute(id, { ...params, path: prepareRemoteToolPath(params.path) }, signal, update) : localWrite.execute(id, params, signal, update); } });
  pi.registerTool({ ...localEdit, execute: (id, params, signal, update) => { const state = remote; return state && routeRemoteTools ? createEditTool(localCwd, { operations: remoteEditOps(state) }).execute(id, { ...params, path: prepareRemoteToolPath(params.path) }, signal, update) : localEdit.execute(id, params, signal, update); } });
  pi.registerTool({ ...localBash, execute: (id, params, signal, update) => { const state = remote; return state && routeRemoteTools ? createBashTool(localCwd, { operations: remoteBashOps(state) }).execute(id, params, signal, update) : localBash.execute(id, params, signal, update); } });

  pi.registerTool({
    ...remoteReadBase,
    name: "ssh_remote_read",
    label: "SSH Remote Read",
    description: "Read a file from a specific configured SSH endpoint without changing the active remote workspace.",
    promptSnippet: "Read a file from a named SSH endpoint",
    parameters: Type.Object({
      endpoint: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
      path: Type.String({ description: "Absolute path on the remote endpoint, or a path relative to that endpoint's persistent cwd" }),
      offset: Type.Optional(Type.Number({ description: "Line number to start from (1-indexed)" })),
      limit: Type.Optional(Type.Number({ description: "Maximum number of lines to read" })),
    }),
    async execute(id, params, signal, update, ctx) {
      const state = await ensureConnected(ctx, params.endpoint, false);
      const { endpoint: _endpoint, ...readParams } = params;
      return createReadTool(localCwd, { operations: remoteReadOps(state) }).execute(id, { ...readParams, path: prepareRemoteToolPath(readParams.path) }, signal, update);
    },
  });

  pi.registerTool({
    ...remoteWriteBase,
    name: "ssh_remote_write",
    label: "SSH Remote Write",
    description: "Write a file on a specific configured SSH endpoint without changing the active remote workspace.",
    promptSnippet: "Write a file on a named SSH endpoint",
    parameters: Type.Object({
      endpoint: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
      path: Type.String({ description: "Absolute path on the remote endpoint, or a path relative to that endpoint's persistent cwd" }),
      content: Type.String({ description: "Complete file content" }),
    }),
    async execute(id, params, signal, update, ctx) {
      const state = await ensureConnected(ctx, params.endpoint, false);
      const { endpoint: _endpoint, ...writeParams } = params;
      return createWriteTool(localCwd, { operations: remoteWriteOps(state) }).execute(id, { ...writeParams, path: prepareRemoteToolPath(writeParams.path) }, signal, update);
    },
  });

  pi.registerTool({
    ...remoteEditBase,
    name: "ssh_remote_edit",
    label: "SSH Remote Edit",
    description: "Apply exact text replacements to a file on a specific configured SSH endpoint without changing the active workspace.",
    promptSnippet: "Edit a file on a named SSH endpoint",
    parameters: Type.Object({
      endpoint: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
      path: Type.String({ description: "Absolute path on the remote endpoint, or a path relative to that endpoint's persistent cwd" }),
      edits: Type.Array(Type.Object({
        oldText: Type.String({ description: "Exact text to replace" }),
        newText: Type.String({ description: "Replacement text" }),
      }), { minItems: 1 }),
    }),
    async execute(id, params, signal, update, ctx) {
      const state = await ensureConnected(ctx, params.endpoint, false);
      const { endpoint: _endpoint, ...editParams } = params;
      return createEditTool(localCwd, { operations: remoteEditOps(state) }).execute(id, { ...editParams, path: prepareRemoteToolPath(editParams.path) }, signal, update);
    },
  });

  pi.registerTool({
    name: "ssh_remote_exec",
    label: "SSH Remote Exec",
    description: "Execute a shell command on one specific SSH endpoint without switching the active workspace. Use this for cross-server inspection and coordination. REQUIRED: endpoint AND command are both mandatory on every call — there is no default server, so you must always pass an explicit endpoint selector (full key, host/IP, user@host, host:port, or unique note prefix); omitting endpoint fails validation with 'must have required properties endpoint'.",
    promptSnippet: "Run a command on a named SSH endpoint",
    promptGuidelines: [
      "Identify the endpoint by its full key, host/IP, user@host, host:port, or a unique key/host/note prefix.",
      "Set a timeout appropriate for the command. Background long-running services explicitly with nohup or an equivalent supervisor.",
    ],
    parameters: Type.Object({
      endpoint: Type.String({ description: `[REQUIRED] ${ENDPOINT_SELECTOR_DESCRIPTION}` }),
      command: Type.String({ description: "[REQUIRED] Remote Bash command" }),
      cwd: Type.Optional(Type.String({ description: "[Optional] One-command working directory override; defaults to the endpoint's persistent cwd" })),
      timeout: Type.Optional(Type.Number({ minimum: 1, maximum: MAX_REMOTE_TIMEOUT_SECONDS, description: `[Optional] Timeout in seconds; defaults to ${DEFAULT_REMOTE_TIMEOUT_SECONDS}` })),
      displayLines: Type.Optional(Type.Integer({ minimum: 1, maximum: DEFAULT_MAX_LINES, description: "[Optional] Collapsed preview lines" })),
      pty: Type.Optional(Type.Boolean({ default: true, description: "[Optional] Allocate a remote pseudo-terminal; gives real Ctrl+C (SIGINT to the process group) on abort. Set false for plain pipe exec (no CRLF/ANSI noise, weaker Ctrl+C). Defaults to true." })),
    }),
    async execute(_id, params, signal, update, ctx) {
      const state = await ensureConnected(ctx, params.endpoint, false);
      if (signal?.aborted) throw new Error("Command aborted");
      const timeoutSeconds = parseRemoteTimeout(params.timeout ?? configuredRemoteTimeout(cacheId(state)));
      const displayLines = parseDisplayLines(params.displayLines ?? configuredDisplayLines());
      const progress = new ExecStreamProgress(update, Math.max(displayLines, 10));
      if (update) update({ content: [], details: undefined });
      let output: Buffer;
      try {
        output = await withReconnectFor(cacheId(state), (client) => execRemote(
          client,
          `cd -- ${quote(params.cwd ?? state.cwd)} && ${params.command}`,
          false,
          timeoutSeconds,
          { signal, pty: params.pty !== false, onData: (chunk) => progress.append(chunk) },
        ));
      } catch (error) {
        progress.finish();
        if (error instanceof Error && error.message === "aborted") {
          const tail = progress.tail();
          const note = params.pty === false
            ? "Command aborted (SIGINT sent; without PTY background children may keep running until their own timeout)"
            : "Command aborted (SIGINT sent to the remote process group; output reflects the partial run)";
          throw new Error(`${tail && tail !== "Remote command completed." ? `${tail}\n\n` : ""}${note}`);
        }
        throw error;
      }
      progress.finish();
      const formatted = formatRemoteOutput(output.toString());
      return {
        content: [{ type: "text", text: formatted.text }],
        details: {
          action: "exec",
          endpoint: cacheId(state),
          cwd: params.cwd ?? state.cwd,
          displayLines: parseDisplayLines(params.displayLines ?? configuredDisplayLines()),
          output: formatted.content,
          truncation: formatted.truncation.truncated ? formatted.truncation : undefined,
          fullOutputPath: formatted.fullOutputPath,
        },
      };
    },
    renderCall(args, theme) {
      return renderRemoteExecCall("ssh_remote_exec", args, theme);
    },
    renderResult(result, { expanded }, theme) {
      return renderRemoteControlResult(result, expanded, theme);
    },
  });

  pi.registerTool({
    name: "ssh_remote_batch",
    label: "SSH Remote Batch",
    description: "Run independent shell jobs across multiple configured SSH endpoints, concurrently by default. Results remain ordered like the input jobs and one failure does not cancel the others.",
    promptSnippet: "Run coordinated commands across multiple SSH endpoints",
    promptGuidelines: [
      "Use one job per endpoint and prefer read-only checks before making coordinated changes.",
      "Set parallel to false when jobs have an ordering dependency, such as starting a head node before workers.",
    ],
    parameters: Type.Object({
      jobs: Type.Array(Type.Object({
        endpoint: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
        command: Type.String({ description: "Remote Bash command" }),
        cwd: Type.Optional(Type.String({ description: "One-command working directory override" })),
        timeout: Type.Optional(Type.Number({ minimum: 1, maximum: MAX_REMOTE_TIMEOUT_SECONDS })),
      }), { minItems: 1, maxItems: 32 }),
      parallel: Type.Optional(Type.Boolean({ description: "Run jobs concurrently; defaults to true" })),
      concurrency: Type.Optional(Type.Integer({ minimum: 1, maximum: 16, description: "Maximum concurrent jobs; defaults to 8" })),
      timeout: Type.Optional(Type.Number({ minimum: 1, maximum: MAX_REMOTE_TIMEOUT_SECONDS, description: "Default timeout for jobs that omit timeout" })),
    }),
    async execute(_id, params, signal, update, ctx) {
      if (signal?.aborted) throw new Error("Command aborted");
      const states: RemoteState[] = [];
      for (const job of params.jobs) states.push(await ensureConnected(ctx, job.endpoint, false));
      const results: Array<{ endpoint: string; ok: boolean; output?: string; error?: string }> = new Array(params.jobs.length);
      const started = new Set<number>();
      // Option B: per-job rolling tail buffer (last lines) fed by execRemote's onData,
      // rendered as a 2-line preview under each running job's status row.
      const jobTails: string[] = new Array(params.jobs.length).fill("");
      const BATCH_TAIL_LINES = 2;
      const BATCH_TAIL_BYTES = 64 * 1024;
      const tailLines = (index: number): string[] => {
        const clean = sanitizePtyOutput(jobTails[index]);
        const lines = clean.replace(/\n+$/, "").split("\n");
        return lines.slice(-BATCH_TAIL_LINES);
      };
      let lastEmit = 0;
      let emitTimer: ReturnType<typeof setTimeout> | undefined;
      const statusLines = () => params.jobs.map((job, index) => {
        const result = results[index];
        const mark = result ? (result.ok ? "ok  " : "fail") : started.has(index) ? "run " : "wait";
        const detail = result ? (result.ok ? "" : `: ${truncateToWidth(result.error ?? "", 100)}`) : started.has(index) ? `: ${truncateToWidth(job.command.replace(/\s+/g, " ").trim(), 100)}` : "";
        const row = `[${index + 1}/${params.jobs.length}] ${mark} ${result?.endpoint ?? job.endpoint}${detail}`;
        const running = started.has(index) && !result;
        if (!running || !jobTails[index]) return row;
        return [row, ...tailLines(index).map((line) => `      | ${truncateToWidth(line, 120)}`)].join("\n");
      }).join("\n");
      const emitStatus = () => {
        lastEmit = Date.now();
        if (update) update({ content: [{ type: "text", text: statusLines() }], details: undefined });
      };
      const scheduleEmit = () => {
        if (!update) return;
        const delay = EXEC_UPDATE_THROTTLE_MS - (Date.now() - lastEmit);
        if (delay <= 0) { if (emitTimer) { clearTimeout(emitTimer); emitTimer = undefined; } emitStatus(); return; }
        if (!emitTimer) emitTimer = setTimeout(() => { emitTimer = undefined; emitStatus(); }, delay);
      };
      if (update) update({ content: [], details: undefined });
      const pushTail = (index: number, chunk: Buffer) => {
        const text = sanitizePtyOutput(chunk.toString("utf8"));
        if (!text) return;
        jobTails[index] = (jobTails[index] + text).slice(-BATCH_TAIL_BYTES);
        scheduleEmit();
      };
      const runJob = async (index: number) => {
        const job = params.jobs[index]!;
        const state = states[index]!;
        started.add(index);
        emitStatus();
        try {
          const timeoutSeconds = parseRemoteTimeout(job.timeout ?? params.timeout ?? configuredRemoteTimeout(cacheId(state)));
          const output = await withReconnectFor(cacheId(state), (client) => execRemote(
            client,
            `cd -- ${quote(job.cwd ?? state.cwd)} && ${job.command}`,
            false,
            timeoutSeconds,
            { signal, onData: (chunk) => pushTail(index, chunk) },
          ));
          results[index] = { endpoint: cacheId(state), ok: true, output: output.toString().trim() || "Command completed." };
        } catch (error) {
          results[index] = { endpoint: cacheId(state), ok: false, error: (error as Error).message };
        }
        if (emitTimer) { clearTimeout(emitTimer); emitTimer = undefined; }
        emitStatus();
      };
      if (params.parallel === false) {
        for (let index = 0; index < params.jobs.length; index++) await runJob(index);
      } else {
        let cursor = 0;
        const workerCount = Math.min(params.concurrency ?? 8, params.jobs.length);
        await Promise.all(Array.from({ length: workerCount }, async () => {
          while (cursor < params.jobs.length) {
            const index = cursor++;
            await runJob(index);
          }
        }));
      }
      if (signal?.aborted) {
        const settled = results.filter(Boolean).length;
        throw new Error(`Batch aborted after ${settled}/${params.jobs.length} jobs:\n${statusLines()}`);
      }
      const combined = results.map((result, index) => result.ok
        ? `===== [${index + 1}] ${result.endpoint} · OK =====\n${result.output}`
        : `===== [${index + 1}] ${result.endpoint} · FAILED =====\n${result.error}`).join("\n\n");
      const formatted = formatRemoteOutput(combined);
      return {
        content: [{ type: "text", text: formatted.text }],
        details: { action: "batch", results, fullOutputPath: formatted.fullOutputPath },
      };
    },
    renderCall(args, theme) {
      const jobs = Array.isArray(args?.jobs) ? args.jobs : [];
      const title = jobs.length === 1 ? "ssh_remote_batch" : `ssh_remote_batch ×${jobs.length}`;
      return renderRemoteExecCall(title, jobs[0], theme);
    },
  });

  const TX_OVERWRITE_ENUM = ["always", "skip", "newer"] as const;
  const TX_OPTS_DOC = {
    overwrite: "always: overwrite; skip: keep existing files; newer: overwrite only when the source is newer than the destination",
  };

  pi.registerTool({
    name: "ssh_remote_put",
    label: "SSH Remote Put (upload)",
    description: "Upload a local file or directory from this machine to one or more SSH servers. Point-to-point with a single endpoint, or point-to-many/fan-out with a targets list. Handles small files up to very large files via parallel SFTP channels, creates destination directories automatically, and preserves directory structure.",
    promptSnippet: "Upload local files to one or more SSH servers",
    promptGuidelines: [
      "localPath resolves against the local process cwd; remotePath and targets are remote (absolute or ~).",
      "For fan-out use targets=[...]; each target accepts a full key, host/IP, user@host, host:port, or note prefix.",
      "Use overwrite=skip or overwrite=newer to avoid re-sending unchanged files in repeated sync runs.",
      "Large files: increase concurrency (default 16 SFTP channels per file) and chunkSize for throughput.",
    ],
    parameters: Type.Object({
      localPath: Type.String({ description: "Local file or directory to upload (relative paths anchor to the local cwd)" }),
      remotePath: Type.String({ description: "Destination on the remote endpoint(s). Directory (contents preserved, directories auto-created) or an exact file path when uploading a single file with no trailing slash" }),
      endpoint: Type.Optional(Type.String({ description: "Single target endpoint (point-to-point)" })),
      targets: Type.Optional(Type.Array(Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }), { minItems: 1, maxItems: 32, description: "Multiple target endpoints for fan-out (point-to-many)" })),
      recursive: Type.Optional(Type.Boolean({ default: true, description: "Transfer directories recursively; required when source is a directory" })),
      overwrite: Type.Optional(StringEnum(TX_OVERWRITE_ENUM, { default: "always", description: TX_OPTS_DOC.overwrite })),
      concurrency: Type.Optional(Type.Integer({ minimum: 1, maximum: 64, default: 16, description: "Parallel SFTP channels per file" })),
      chunkSize: Type.Optional(Type.Integer({ minimum: 1024, maximum: 1048576, default: 32768, description: "SFTP chunk size in bytes" })),
      parallel: Type.Optional(Type.Integer({ minimum: 1, maximum: 16, default: 4, description: "Max endpoints transferred concurrently (fan-out)" })),
    }),
    async execute(_id, params, signal, onUpdate, ctx) {
      const states = await resolveTargetStates(ctx, params.endpoint, params.targets);
      if (!states.length) throw new Error("No target endpoints resolved");
      const localAbs = resolveLocalPath(params.localPath);
      const progress = new TxProgress(onUpdate, "ssh_remote_put");
      if (onUpdate) onUpdate({ content: [], details: undefined });
      progress.message(`Uploading ${localAbs} -> ${states.length} server(s)`);
      const started = Date.now();
      const results = await runFanOut(states, (state) => putToState(
        state,
        localAbs,
        resolveRemotePath(state, params.remotePath),
        {
          overwrite: params.overwrite ?? "always",
          concurrency: params.concurrency ?? 16,
          chunkSize: params.chunkSize ?? 32768,
          recursive: params.recursive ?? true,
        },
        progress,
        signal,
      ), params.parallel ?? 4);
      const lines = results.map((r, i) => `[${i + 1}] ${cacheId(states[i]!)} ok: ${r.files} file(s), ${formatSize(r.bytes)}${r.skipped ? `, ${r.skipped} skipped` : ""} in ${((Date.now() - r.startedAt) / 1000).toFixed(1)}s`).join("\n");
      const totals = results.reduce((a, b) => ({ files: a.files + b.files, bytes: a.bytes + b.bytes, skipped: a.skipped + b.skipped }), { files: 0, bytes: 0, skipped: 0 });
      const text = `Uploaded to ${results.length} server(s):\n${lines}\nTotal: ${totals.files} file(s), ${formatSize(totals.bytes)}${totals.skipped ? `, ${totals.skipped} skipped` : ""}, in ${((Date.now() - started) / 1000).toFixed(1)}s`;
      return {
        content: [{ type: "text", text }],
        details: { action: "put", localPath: localAbs, results: results.map((r, i) => ({ endpoint: cacheId(states[i]!), files: r.files, bytes: r.bytes, skipped: r.skipped, durationMs: Date.now() - r.startedAt })), totalFiles: totals.files, totalBytes: totals.bytes, totalSkipped: totals.skipped, durationMs: Date.now() - started },
      };
    },
  });

  pi.registerTool({
    name: "ssh_remote_get",
    label: "SSH Remote Get (download)",
    description: "Download a file or directory from one SSH server to this machine. Handles small files up to very large files via parallel SFTP channels, creates local directories automatically, and preserves directory structure.",
    promptSnippet: "Download files from an SSH server to the local machine",
    promptGuidelines: [
      "remotePath is the source on the server (absolute or ~); localPath is a directory, or an exact file path when downloading a single file.",
      "Use overwrite=skip or overwrite=newer to avoid re-downloading files you already have.",
    ],
    parameters: Type.Object({
      endpoint: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
      remotePath: Type.String({ description: "Source file or directory on the remote server (absolute, ~, or relative to the endpoint cwd)" }),
      localPath: Type.String({ description: "Local destination directory (contents preserved), or an exact file path when downloading a single file" }),
      recursive: Type.Optional(Type.Boolean({ default: true, description: "Transfer directories recursively; required when source is a directory" })),
      overwrite: Type.Optional(StringEnum(TX_OVERWRITE_ENUM, { default: "always", description: TX_OPTS_DOC.overwrite })),
      concurrency: Type.Optional(Type.Integer({ minimum: 1, maximum: 64, default: 16, description: "Parallel SFTP channels per file" })),
      chunkSize: Type.Optional(Type.Integer({ minimum: 1024, maximum: 1048576, default: 32768, description: "SFTP chunk size in bytes" })),
    }),
    async execute(_id, params, signal, onUpdate, ctx) {
      const state = await ensureConnected(ctx, params.endpoint, false);
      const remoteSource = resolveRemotePath(state, params.remotePath);
      const localTarget = resolveLocalPath(params.localPath);
      const progress = new TxProgress(onUpdate, "ssh_remote_get");
      if (onUpdate) onUpdate({ content: [], details: undefined });
      progress.message(`Downloading ${remoteSource} -> ${localTarget}`);
      const started = Date.now();
      const stats = await getFromState(
        state,
        remoteSource,
        localTarget,
        {
          overwrite: params.overwrite ?? "always",
          concurrency: params.concurrency ?? 16,
          chunkSize: params.chunkSize ?? 32768,
          recursive: params.recursive ?? true,
        },
        progress,
        signal,
      );
      const text = `Downloaded ${stats.files} file(s), ${formatSize(stats.bytes)}${stats.skipped ? `, ${stats.skipped} skipped` : ""}, in ${((Date.now() - started) / 1000).toFixed(1)}s -> ${localTarget}`;
      return {
        content: [{ type: "text", text }],
        details: { action: "get", endpoint: cacheId(state), remotePath: remoteSource, localPath: localTarget, files: stats.files, bytes: stats.bytes, skipped: stats.skipped, durationMs: Date.now() - started },
      };
    },
  });

  pi.registerTool({
    name: "ssh_remote_transfer",
    label: "SSH Remote Transfer (server to server)",
    description: "Copy a file or directory from one SSH server to one or more other SSH servers, relayed through this machine. Point-to-point with a single target, or point-to-many/fan-out with a targets list. Default stream mode pipes through this process (bounded memory, no local disk); stage mode uses fastGet/fastPut on both legs via a local temp file (faster, needs local disk equal to file size).",
    promptSnippet: "Copy files between SSH servers",
    promptGuidelines: [
      "source and target/targets are endpoint selectors; sourcePath is on the source server; targetPath is the destination on each target server.",
      "Server-to-server copies always relay through this machine and never require the servers to reach each other.",
      "For very large files, stream mode keeps memory bounded; stage mode is faster but uses local disk equal to the largest file.",
    ],
    parameters: Type.Object({
      source: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
      sourcePath: Type.String({ description: "Source file or directory on the source server (absolute, ~, or relative to the endpoint cwd)" }),
      target: Type.Optional(Type.String({ description: "Single destination endpoint (point-to-point)" })),
      targets: Type.Optional(Type.Array(Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }), { minItems: 1, maxItems: 32, description: "Multiple destination endpoints for fan-out (point-to-many)" })),
      targetPath: Type.String({ description: "Destination on each target server: directory (contents preserved, auto-created) or an exact file path when copying a single file" }),
      via: Type.Optional(StringEnum(["stream", "stage"] as const, { default: "stream", description: "stream: pipe through this process (bounded memory); stage: stage on local disk first (faster, needs free disk = file size)" })),
      recursive: Type.Optional(Type.Boolean({ default: true, description: "Transfer directories recursively; required when source is a directory" })),
      overwrite: Type.Optional(StringEnum(TX_OVERWRITE_ENUM, { default: "always", description: TX_OPTS_DOC.overwrite })),
      concurrency: Type.Optional(Type.Integer({ minimum: 1, maximum: 64, default: 16, description: "Parallel SFTP channels per file (stage mode)" })),
      chunkSize: Type.Optional(Type.Integer({ minimum: 1024, maximum: 1048576, default: 32768, description: "SFTP chunk size in bytes" })),
      parallel: Type.Optional(Type.Integer({ minimum: 1, maximum: 16, default: 2, description: "Max target servers relayed concurrently (fan-out)" })),
    }),
    async execute(_id, params, signal, onUpdate, ctx) {
      const srcState = await ensureConnected(ctx, params.source, false);
      const dstStates = await resolveTargetStates(ctx, params.target, params.targets);
      if (!dstStates.length) throw new Error("No target endpoints resolved");
      const srcPath = resolveRemotePath(srcState, params.sourcePath);
      const progress = new TxProgress(onUpdate, "ssh_remote_transfer");
      if (onUpdate) onUpdate({ content: [], details: undefined });
      progress.message(`Transferring ${srcPath} -> ${dstStates.length} target server(s) (via ${params.via ?? "stream"})`);
      const started = Date.now();
      const results = await runFanOut(dstStates, (state) => transferToState(
        srcState,
        srcPath,
        state,
        resolveRemotePath(state, params.targetPath),
        {
          overwrite: params.overwrite ?? "always",
          concurrency: params.concurrency ?? 16,
          chunkSize: params.chunkSize ?? 32768,
          via: params.via ?? "stream",
          recursive: params.recursive ?? true,
        },
        progress,
        signal,
      ), params.parallel ?? 2);
      const lines = results.map((r, i) => `[${i + 1}] ${cacheId(dstStates[i]!)} ok: ${r.files} file(s), ${formatSize(r.bytes)}${r.skipped ? `, ${r.skipped} skipped` : ""} in ${((Date.now() - r.startedAt) / 1000).toFixed(1)}s`).join("\n");
      const totals = results.reduce((a, b) => ({ files: a.files + b.files, bytes: a.bytes + b.bytes, skipped: a.skipped + b.skipped }), { files: 0, bytes: 0, skipped: 0 });
      const text = `Transferred to ${results.length} target(s):\n${lines}\nTotal: ${totals.files} file(s), ${formatSize(totals.bytes)}${totals.skipped ? `, ${totals.skipped} skipped` : ""}, in ${((Date.now() - started) / 1000).toFixed(1)}s (relayed through local)`;
      return {
        content: [{ type: "text", text }],
        details: { action: "transfer", source: cacheId(srcState), sourcePath: srcPath, via: params.via ?? "stream", results: results.map((r, i) => ({ endpoint: cacheId(dstStates[i]!), files: r.files, bytes: r.bytes, skipped: r.skipped, durationMs: Date.now() - r.startedAt })), totalFiles: totals.files, totalBytes: totals.bytes, totalSkipped: totals.skipped, durationMs: Date.now() - started },
      };
    },
  });

  pi.registerTool({
    name: "ssh_remote_password",
    label: "SSH Remote Password (decode)",
    description: `Decode the plaintext password for a configured SSH endpoint from the local encrypted credential store (in-memory cache first, then the persisted backend: Windows DPAPI, macOS Keychain, libsecret, or the local AES-256-GCM key file). Backends available here: ${persistentCredentials.backends.join(", ")}. Use it when a remote step genuinely needs the password — e.g. elevating with sudo -S, configuring another service, or feeding a jump host — and the interactive prompt is not available to the agent.`,
    promptSnippet: "Decode a saved SSH endpoint password",
    promptGuidelines: [
      "DECODED PASSWORDS ARE PLAINTEXT and leak into the model context, transcripts, and tool logs. Call this only when the password is actually needed for the current task; do not echo it back unless the task requires it.",
      "A password is only decodeable for an endpoint that was connected at least once with saving enabled (persisted to ~/.pi/agent/ssh-remote-credentials.json through Windows DPAPI, macOS Keychain, libsecret, or the local AES-256-GCM key file ~/.pi/agent/ssh-remote-secret.key).",
      "Endpoint can be a full key, host/IP, user@host, host:port, or a unique prefix/note; it does not need to be currently connected.",
    ],
    parameters: Type.Object({
      endpoint: Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION }),
    }),
    async execute(_id, params, _signal, _update, ctx) {
      if (!persistentCredentials.available) {
        throw new Error("No credential backend is available in this environment; saved passwords cannot be decoded");
      }
      const decoded = await getDecodedPassword(params.endpoint);
      return {
        content: [{ type: "text", text: `Decoded password for ${decoded.endpoint} (source: ${decoded.source}): ${decoded.password}` }],
        details: { endpoint: decoded.endpoint, source: decoded.source },
      };
    },
  });

  pi.registerTool({
    name: "ssh_remote_control",
    label: "SSH Remote Control",
    description: "Connect and retain multiple SSH endpoints, select the default endpoint, explicitly enable or disable transparent remote routing, inspect all live connections, change endpoint state, decode a saved endpoint password, or disconnect one/all endpoints. Connections never change built-in tool routing by themselves.",
    promptSnippet: "Control the multi-server SSH pool, endpoint selection, passwords, and explicit local/remote routing",
    promptGuidelines: [
      "Use ssh_remote_control when the user asks the agent to connect, activate, reconnect, inspect, or disconnect SSH endpoints.",
      "Use action endpoints to list every configured endpoint (connected or not) before choosing a selector; copy the exact key instead of retyping an address.",
      "Use ssh_remote_control with action chdir when the user asks to change the remote working directory; do not emulate a persistent directory change with action exec and a one-command cwd.",
      "Use action password to decode a saved endpoint's plaintext password (e.g. for remote sudo -S); treat the decoded value as sensitive and do not log it unless required.",
      `Always set timeout for ssh_remote_control remote exec commands; it defaults to ${DEFAULT_REMOTE_TIMEOUT_SECONDS} seconds when omitted.`,
      "Connecting or selecting an endpoint never enables remote routing by itself. Use action route with routing remote only when the user explicitly wants built-in tools redirected.",
    ],
    parameters: Type.Object({
      action: StringEnum(["connect", "activate", "route", "reconnect", "password", "status", "connections", "endpoints", "disconnect", "forget", "forward", "unforward", "exec", "chdir", "note", "local"] as const),
      command: Type.Optional(Type.String({ description: "SSH command for connect, such as ssh root@host -p 22; optionally selects the endpoint for note" })),
      endpoint: Type.Optional(Type.String({ description: ENDPOINT_SELECTOR_DESCRIPTION })),
      activate: Type.Optional(Type.Boolean({ description: "For connect: select this endpoint as the default target; defaults to false and never changes tool routing" })),
      routing: Type.Optional(StringEnum(["local", "remote"] as const, { description: "Required for route: choose where built-in read/write/edit/bash tools run" })),
      all: Type.Optional(Type.Boolean({ description: "For disconnect: apply to all live endpoints; for forget: disconnect all and delete all saved passwords" })),
      note: Type.Optional(Type.String({ description: "Endpoint note for the note action; omit or use an empty string to clear it" })),
      cwd: Type.Optional(Type.String({ description: "Remote working directory; required for chdir, and a one-command override for exec" })),
      forwards: Type.Optional(Type.String({ description: "Space-separated LOCAL_PORT:REMOTE_HOST:REMOTE_PORT mappings; defaults to ssh-remote-config.json" })),
      remoteCommand: Type.Optional(Type.String({ description: "Remote shell command for the exec action" })),
      timeout: Type.Optional(Type.Number({ minimum: 1, maximum: MAX_REMOTE_TIMEOUT_SECONDS, description: `Remote command timeout in seconds; defaults to ${DEFAULT_REMOTE_TIMEOUT_SECONDS}` })),
      displayLines: Type.Optional(Type.Integer({ minimum: 1, maximum: DEFAULT_MAX_LINES, description: "Collapsed visual lines for exec output; defaults to the /remote config display-lines setting (5 initially)" })),
    }),
    async execute(_id, params, _signal, _update, ctx) {
      if (params.action === "status" || params.action === "connections") {
        const mappings = [...forwardServers.keys()].sort((a, b) => a - b);
        const pool = connectionSnapshot();
        const rows = pool.map((entry) => `${entry.selected ? "*" : " "} ${entry.endpoint}  cwd=${entry.cwd}${entry.note ? `  note=${entry.note}` : ""}${entry.passwordSaved ? "  password=saved" : ""}`);
        const text = `${connections.size} SSH connection(s); tool routing: ${remote && routeRemoteTools ? `remote via ${cacheId(remote)}` : "local"}${mappings.length ? `; forwarded local ports: ${mappings.join(", ")}` : ""}\n${rows.join("\n") || "No live SSH connections"}`;
        return { content: [{ type: "text", text }], details: { connected: connections.size > 0, connectionCount: connections.size, connections: pool, selectedEndpoint: remote ? cacheId(remote) : undefined, cwd: remote?.cwd, toolRouting: remote && routeRemoteTools ? "remote" : "local", configPath: REMOTE_CONFIG_FILE, credentialsPath: CREDENTIALS_FILE, credentialBackend: persistentCredentials.label, credentialBackends: persistentCredentials.backends, forwardedPorts: mappings } };
      }
      if (params.action === "endpoints") {
        const config = loadRemoteConfig();
        const keys = Object.keys(config.endpoints ?? {});
        const rows = keys.map((key) => {
          const saved = config.endpoints?.[key];
          const live = connections.get(key);
          const flags = [
            live ? "connected" : "configured",
            live ? `cwd=${live.cwd}` : saved?.remoteCwd ? `cwd=${saved.remoteCwd}` : undefined,
            key === config.activeEndpoint ? "active" : undefined,
            saved?.note?.trim(),
            persistentCredentials.has(key) ? "password=saved" : undefined,
          ].filter(Boolean).join("; ");
          return `- ${key}  (${flags})`;
        });
        const text = keys.length
          ? `Configured endpoints (${keys.length}); pass one of these exact keys as the endpoint argument:\n${rows.join("\n")}`
          : "No endpoints are configured yet; use action=connect with an ssh command first.";
        return { content: [{ type: "text", text }], details: { endpointCount: keys.length, endpoints: keys, connected: connections.size > 0, connectionCount: connections.size, selectedEndpoint: remote ? cacheId(remote) : undefined, toolRouting: remote && routeRemoteTools ? "remote" : "local", configPath: REMOTE_CONFIG_FILE } };
      }
      if (params.action === "disconnect" || params.action === "forget") {
        const forget = params.action === "forget";
        if (forget) {
          if (params.all) {
            const result = forgetAllPasswords(ctx);
            return { content: [{ type: "text", text: `Disconnected ${result.disconnected} SSH endpoint(s) and deleted ${result.forgotten} saved password(s).` }], details: { connected: false, ...result, connectionCount: 0, connections: [] } };
          }
          const endpointKey = forgetEndpoint(ctx, params.endpoint);
          return { content: [{ type: "text", text: `Disconnected ${endpointKey} if needed and deleted its saved password.` }], details: { connected: connections.size > 0, endpoint: endpointKey, connectionCount: connections.size, connections: connectionSnapshot() } };
        }
        if (params.all) {
          const count = disconnectAll(ctx, false);
          return { content: [{ type: "text", text: `Disconnected ${count} SSH endpoint(s).` }], details: { connected: false, disconnected: count, connectionCount: 0, connections: [] } };
        }
        const endpointKey = disconnectEndpoint(ctx, params.endpoint, forget);
        return { content: [{ type: "text", text: `Disconnected ${endpointKey}.` }], details: { connected: connections.size > 0, endpoint: endpointKey, connectionCount: connections.size, connections: connectionSnapshot() } };
      }
      if (params.action === "local") {
        routeRemoteTools = false;
        status(ctx);
        return { content: [{ type: "text", text: `Built-in tools now run locally; ${connections.size} SSH connection(s) remain available.` }], details: { connected: connections.size > 0, toolRouting: "local" } };
      }
      if (params.action === "route") {
        if (!params.routing) throw new Error("routing is required for route: local or remote");
        if (params.routing === "local") {
          routeRemoteTools = false;
          status(ctx);
          return { content: [{ type: "text", text: `Built-in tools now run locally; ${connections.size} SSH connection(s) remain available.` }], details: { connectionCount: connections.size, connections: connectionSnapshot(), toolRouting: "local" } };
        }
        const state = await ensureConnected(ctx, params.endpoint, true);
        remote = state;
        routeRemoteTools = true;
        credentialCache.resume = { command: state.command, cwd: state.cwd };
        saveEndpointConfig(state.command, { remoteCwd: state.cwd }, true);
        status(ctx);
        return { content: [{ type: "text", text: `Built-in tools now route to ${cacheId(state)}:${state.cwd}.` }], details: { connectionCount: connections.size, connections: connectionSnapshot(), selectedEndpoint: cacheId(state), toolRouting: "remote" } };
      }
      if (params.action === "activate") {
        const state = await ensureConnected(ctx, params.endpoint, false);
        remote = state;
        credentialCache.resume = { command: state.command, cwd: state.cwd };
        lastCommand = state.command;
        saveEndpointConfig(state.command, { remoteCwd: state.cwd }, true);
        status(ctx);
        return { content: [{ type: "text", text: `Selected SSH endpoint: ${endpointDisplayLabel(state)}:${state.cwd}; built-in tools remain ${routeRemoteTools ? "remote-routed" : "local"}.` }], details: { connected: true, connectionCount: connections.size, connections: connectionSnapshot(), selectedEndpoint: cacheId(state), cwd: state.cwd, toolRouting: routeRemoteTools ? "remote" : "local" } };
      }
      if (params.action === "reconnect") {
        const endpointKey = params.endpoint ? resolveEndpointKey(params.endpoint) : remote ? cacheId(remote) : resolveEndpointKey(undefined);
        const state = await reconnectEndpoint(endpointKey);
        return { content: [{ type: "text", text: `Reconnected: ${endpointDisplayLabel(state)}:${state.cwd}` }], details: { connected: true, cwd: state.cwd } };
      }
      if (params.action === "password") {
        if (!persistentCredentials.available) {
          throw new Error("No credential backend is available in this environment; saved passwords cannot be decoded");
        }
        const decoded = await getDecodedPassword(params.endpoint);
        return {
          content: [{ type: "text", text: `Decoded password for ${decoded.endpoint} (source: ${decoded.source}): ${decoded.password}` }],
          details: { endpoint: decoded.endpoint, source: decoded.source },
        };
      }
      if (params.action === "unforward") {
        await stopForwards();
        return { content: [{ type: "text", text: "Closed all extension-managed SSH port forwards." }], details: { forwardedPorts: [] } };
      }
      if (params.action === "forward") {
        const state = await ensureConnected(ctx);
        const values = params.forwards?.trim().split(/\s+/).filter(Boolean) ?? configuredForwards(state.command);
        if (!values.length) throw new Error(`No port mappings configured in ${REMOTE_CONFIG_FILE}`);
        const specs = values.map(parseForwardSpec);
        for (const spec of specs) await startForward(state, spec);
        routeRemoteTools = false;
        if (currentCtx) status(currentCtx);
        const ports = specs.map((spec) => spec.localPort);
        return { content: [{ type: "text", text: `Forwarded local ports: ${ports.join(", ")}; tools remain local.` }], details: { toolRouting: "local", forwardedPorts: ports } };
      }
      if (params.action === "chdir") {
        const state = await ensureConnected(ctx, params.endpoint, params.endpoint === undefined);
        if (!params.cwd) throw new Error("cwd is required for chdir");
        const resolved = await changeRemoteCwd(params.cwd, ctx, state);
        return { content: [{ type: "text", text: `Remote working directory (${cacheId(state)}): ${resolved}` }], details: { connected: true, endpoint: cacheId(state), cwd: resolved } };
      }
      if (params.action === "note") {
        const selectedKey = params.endpoint ? resolveEndpointKey(params.endpoint) : undefined;
        const command = params.command || (selectedKey ? loadRemoteConfig().endpoints?.[selectedKey]?.sshCommand : undefined) || lastCommand || activeSshCommand();
        if (!command) throw new Error("No SSH endpoint configured; connect or select an endpoint first");
        const note = params.note?.trim() || undefined;
        saveEndpointConfig(command, { note });
        if (remote && cacheId(remote) === cacheId(parseSshCommand(command)) && currentCtx) status(currentCtx);
        const label = parseSshCommand(command).label;
        return {
          content: [{ type: "text", text: note ? `SSH remote note updated (${label}): ${note}` : `SSH remote note cleared (${label})` }],
          details: { endpoint: label, note },
        };
      }
      if (params.action === "exec") {
        const state = await ensureConnected(ctx, params.endpoint, params.endpoint === undefined);
        if (!params.remoteCommand) throw new Error("remoteCommand is required for exec");
        const cdTarget = params.cwd === undefined ? standaloneCdTarget(params.remoteCommand) : undefined;
        if (cdTarget !== undefined) {
          const resolved = await changeRemoteCwd(cdTarget, ctx, state);
          return { content: [{ type: "text", text: resolved }], details: { connected: true, cwd: resolved } };
        }
        const displayLines = parseDisplayLines(params.displayLines ?? configuredDisplayLines());
        const timeoutSeconds = parseRemoteTimeout(params.timeout ?? configuredRemoteTimeout(cacheId(state)));
        const output = await withReconnectFor(cacheId(state), (client) => execRemote(
          client,
          `cd -- ${quote(params.cwd ?? state.cwd)} && ${params.remoteCommand}`,
          false,
          timeoutSeconds,
        ));
        const formatted = formatRemoteOutput(output.toString());
        return {
          content: [{ type: "text", text: formatted.text }],
          details: {
            action: "exec",
            connected: true,
            cwd: state.cwd,
            displayLines,
            output: formatted.content,
            truncation: formatted.truncation.truncated ? formatted.truncation : undefined,
            fullOutputPath: formatted.fullOutputPath,
          },
        };
      }
      const command = params.command || (params.endpoint ? loadRemoteConfig().endpoints?.[resolveEndpointKey(params.endpoint)]?.sshCommand : undefined) || lastCommand || activeSshCommand();
      if (!command) throw new Error(`No SSH endpoint configured. Set ${REMOTE_CONFIG_FILE} or pass command.`);
      const state = await connectInteractive(command, ctx, params.cwd ?? configuredCwd(command), params.activate === true);
      if (!state) throw new Error(lastConnectionError || "SSH remote connection was cancelled or failed");
      return { content: [{ type: "text", text: `Connected: ${endpointDisplayLabel(state)}:${state.cwd}; ${connections.size} connection(s) live; built-in tools: ${routeRemoteTools ? `remote via ${remote ? cacheId(remote) : "none"}` : "local"}.` }], details: { connected: true, connectionCount: connections.size, connections: connectionSnapshot(), selectedEndpoint: remote ? cacheId(remote) : undefined, cwd: state.cwd, toolRouting: routeRemoteTools ? "remote" : "local", configPath: REMOTE_CONFIG_FILE } };
    },
    renderResult(result, { expanded }, theme) {
      return renderRemoteControlResult(result, expanded, theme);
    },
  });

  pi.registerCommand("remote", {
    description: "Manage a multi-server SSH pool: /remote ssh ... | use ENDPOINT | on | off | connections | disconnect [ENDPOINT|--all] | config | exec | cd",
    handler: async (args, ctx) => {
      const input = args.trim().replace(/^\/?remote(?:\s+|$)/i, "").trim();
      const action = input.toLowerCase();
      if (action === "config") {
        const config = loadRemoteConfig();
        const rows = Object.entries(config.endpoints ?? {}).map(([key, endpoint]) => {
          const active = key === config.activeEndpoint ? "*" : " ";
          return `${active} ${key}\n    note: ${endpoint.note || "none"}\n    SSH: ${endpoint.sshCommand}\n    cwd: ${endpoint.remoteCwd || FALLBACK_REMOTE_CWD}\n    forward: ${endpoint.forwards?.join(", ") || "none"}\n    password: ${persistentCredentials.backendFor(key) ? `saved with ${persistentCredentials.backendFor(key)}` : "not saved"}`;
        });
        ctx.ui.notify(`SSH remote configuration: ${REMOTE_CONFIG_FILE}\nDisplay lines: ${configuredDisplayLines(config)}\n${rows.join("\n") || "No saved endpoints"}`, "info");
        return;
      }
      if (/^ssh\s+/i.test(input)) {
        const sshArguments = input.replace(/^ssh\s+/i, "").trim();
        const command = `ssh ${sshArguments}`;
        try { parseSshCommand(command); }
        catch (error) { ctx.ui.notify((error as Error).message, "error"); return; }
        saveEndpointConfig(command, {}, false);
        lastCommand = command;
        await connectInteractive(command, ctx, undefined, false);
        return;
      }
      if (/^(?:config\s+)?use\s+/i.test(input)) {
        const requested = input.replace(/^(?:config\s+)?use\s+/i, "").trim();
        try {
          const key = resolveEndpointKey(requested);
          const config = loadRemoteConfig();
          const command = config.endpoints?.[key]?.sshCommand;
          if (!command) throw new Error(`Endpoint has no SSH command: ${key}`);
          const state = connections.get(key) ?? await connectInteractive(command, ctx, configuredCwd(command), false);
          if (!state) return;
          remote = state;
          credentialCache.resume = { command: state.command, cwd: state.cwd };
          saveRemoteConfig({ ...config, activeEndpoint: key });
          lastCommand = command;
          status(ctx);
          ctx.ui.notify(`Selected SSH endpoint: ${key}:${state.cwd}; built-in tools remain ${routeRemoteTools ? "remote-routed" : "local"}`, "info");
        } catch (error) { ctx.ui.notify((error as Error).message, "error"); }
        return;
      }
      if (/^config\s+note(?:\s+|$)/i.test(input)) {
        const value = input.replace(/^config\s+note\s*/i, "").trim();
        if (!value) { ctx.ui.notify("Use /remote config note TEXT or /remote config note --clear", "error"); return; }
        const command = lastCommand || activeSshCommand();
        if (!command) { ctx.ui.notify("Configure an SSH endpoint first", "error"); return; }
        const note = value.toLowerCase() === "--clear" ? undefined : value;
        saveEndpointConfig(command, { note });
        if (remote && cacheId(remote) === cacheId(parseSshCommand(command))) status(ctx);
        ctx.ui.notify(note ? `SSH remote note updated (${parseSshCommand(command).label}): ${note}` : `SSH remote note cleared (${parseSshCommand(command).label})`, "info");
        return;
      }
      if (/^config\s+display-lines\s+/i.test(input)) {
        try {
          const displayLines = parseDisplayLines(input.replace(/^config\s+display-lines\s+/i, "").trim());
          saveRemoteConfig({ ...loadRemoteConfig(), displayLines });
          ctx.ui.notify(`SSH remote command preview updated: ${displayLines} lines`, "info");
        } catch (error) { ctx.ui.notify((error as Error).message, "error"); }
        return;
      }
      if (/^config\s+cwd\s+/i.test(input)) {
        const remoteCwd = input.replace(/^config\s+cwd\s+/i, "").trim();
        const command = lastCommand || activeSshCommand();
        if (!command) { ctx.ui.notify("Configure an SSH endpoint first", "error"); return; }
        saveEndpointConfig(command, { remoteCwd });
        ctx.ui.notify(`Default SSH remote directory updated (${parseSshCommand(command).label}): ${remoteCwd}`, "info");
        return;
      }
      if (/^config\s+forward(?:\s+|$)/i.test(input)) {
        const forwards = input.replace(/^config\s+forward\s*/i, "").trim().split(/\s+/).filter(Boolean);
        try { forwards.forEach(parseForwardSpec); }
        catch (error) { ctx.ui.notify((error as Error).message, "error"); return; }
        const command = lastCommand || activeSshCommand();
        if (!command) { ctx.ui.notify("Configure an SSH endpoint first", "error"); return; }
        saveEndpointConfig(command, { forwards });
        ctx.ui.notify(`SSH remote port-forward configuration updated (${parseSshCommand(command).label}): ${forwards.join(", ") || "none"}`, "info");
        return;
      }
      if (/^forward(?:\s+|$)/i.test(input)) {
        try {
          const state = await ensureConnected(ctx);
          const supplied = input.replace(/^forward\s*/i, "").trim();
          const values = supplied ? supplied.split(/\s+/) : configuredForwards(state.command);
          if (!values.length) throw new Error("No port forwards configured; use /remote config forward LOCAL_PORT:REMOTE_HOST:REMOTE_PORT");
          const specs = values.map(parseForwardSpec);
          for (const spec of specs) await startForward(state, spec);
          routeRemoteTools = false;
          status(ctx);
          ctx.ui.notify(`SSH remote port forwarding started; tools remain local in ${localCwd}: ${specs.map((spec) => `127.0.0.1:${spec.localPort}`).join(", ")}`, "info");
        } catch (error) { ctx.ui.notify(`SSH remote port forwarding failed: ${(error as Error).message}`, "error"); }
        return;
      }
      if (action === "unforward") {
        await stopForwards();
        ctx.ui.notify("Closed all extension-managed SSH remote port forwards", "info");
        return;
      }
      if (/^exec\s+/i.test(input)) {
        try {
          const state = await ensureConnected(ctx);
          let execInput = input.replace(/^exec\s+/i, "").trim();
          let displayLines = configuredDisplayLines();
          let timeoutSeconds = DEFAULT_REMOTE_TIMEOUT_SECONDS;
          while (execInput.startsWith("--")) {
            const option = execInput.match(/^--(lines|timeout)\s+(\S+)\s+([\s\S]+)$/i);
            if (!option) throw new Error("Expected --lines N or --timeout SECONDS followed by a command");
            if (option[1]!.toLowerCase() === "lines") displayLines = parseDisplayLines(option[2]);
            else timeoutSeconds = parseRemoteTimeout(option[2]);
            execInput = option[3]!;
          }
          const output = (await withReconnect((client) => execRemote(
            client,
            `cd -- ${quote(state.cwd)} && ${execInput}`,
            false,
            timeoutSeconds,
          ))).toString().trim();
          const formatted = formatRemoteOutput(output);
          const preview = previewRemoteOutput(formatted.content, displayLines);
          const omitted = formatted.truncation.totalLines > displayLines
            ? `\n\n[Showing last ${Math.min(displayLines, formatted.truncation.totalLines)} of ${formatted.truncation.totalLines} lines]`
            : "";
          const fullOutput = formatted.fullOutputPath ? `\n[Full output: ${formatted.fullOutputPath}]` : "";
          ctx.ui.notify(`${preview}${omitted}${fullOutput}`, "info");
        } catch (error) { ctx.ui.notify(`SSH remote command failed: ${(error as Error).message}`, "error"); }
        return;
      }
      if (["off", "local", "exit"].includes(action)) {
        routeRemoteTools = false;
        status(ctx);
        ctx.ui.notify(`Built-in tools now run locally; ${connections.size} SSH connection(s) remain available`, "info");
        return;
      }
      if (["on", "remote"].includes(action)) {
        try {
          const state = await ensureConnected(ctx, undefined, true);
          remote = state;
          routeRemoteTools = true;
          credentialCache.resume = { command: state.command, cwd: state.cwd };
          saveEndpointConfig(state.command, { remoteCwd: state.cwd }, true);
          status(ctx);
          ctx.ui.notify(`Built-in tools now route to ${cacheId(state)}:${state.cwd}`, "info");
        } catch (error) { ctx.ui.notify((error as Error).message, "error"); }
        return;
      }
      if (/^disconnect(?:\s+|$)/i.test(input) || /^forget(?:\s+|$)/i.test(input)) {
        const forget = /^forget/i.test(input);
        const selector = input.replace(/^(?:disconnect|forget)\s*/i, "").trim();
        try {
          if (forget && selector === "--all") {
            const result = forgetAllPasswords(ctx);
            ctx.ui.notify(`Disconnected ${result.disconnected} SSH endpoint(s) and deleted ${result.forgotten} saved password(s)`, "info");
          } else if (forget) {
            const endpointKey = forgetEndpoint(ctx, selector || undefined);
            ctx.ui.notify(`Disconnected ${endpointKey} if needed and deleted its saved password`, "info");
          } else if (selector === "--all") {
            const count = disconnectAll(ctx, false);
            ctx.ui.notify(`Disconnected ${count} SSH endpoint(s)`, "info");
          } else {
            const endpointKey = disconnectEndpoint(ctx, selector || undefined, false);
            ctx.ui.notify(`Disconnected ${endpointKey}`, "info");
          }
        } catch (error) { ctx.ui.notify((error as Error).message, "error"); }
        return;
      }
      if (["status", "connections"].includes(action)) {
        const rows = [...connections.entries()].map(([key, state]) => `${remote && cacheId(remote) === key ? "*" : " "} ${key}  cwd=${state.cwd}`);
        ctx.ui.notify(`${connections.size} SSH connection(s); tools: ${remote && routeRemoteTools ? `remote via ${cacheId(remote)}` : "local"}\n${rows.join("\n") || "No live SSH connections"}`, "info");
        return;
      }
      if (["reload", "reconnect"].includes(action)) {
        try { await reconnectRemote(); }
        catch (error) { ctx.ui.notify(`SSH remote reconnection failed: ${(error as Error).message}`, "error"); }
        return;
      }
      if (/^password(?:\s+|$)/i.test(input)) {
        const selector = input.replace(/^password\s*/i, "").trim() || undefined;
        try {
          if (!persistentCredentials.available) throw new Error("No credential backend is available in this environment");
          const decoded = await getDecodedPassword(selector);
          ctx.ui.notify(`Decoded password for ${decoded.endpoint} (source: ${decoded.source}): ${decoded.password}`, "info");
        } catch (error) { ctx.ui.notify(`SSH remote password decode failed: ${(error as Error).message}`, "error"); }
        return;
      }
      if (/^cd(?:\s+|$)/i.test(input)) {
        if (!remote) { ctx.ui.notify("Connect to SSH remote first", "error"); return; }
        const requested = input.replace(/^cd\s*/i, "").trim() || FALLBACK_REMOTE_CWD;
        try {
          const resolved = await changeRemoteCwd(requested, ctx);
          ctx.ui.notify(`SSH remote path: ${resolved}`, "info");
        } catch (error) { ctx.ui.notify(`Failed to change SSH remote path: ${(error as Error).message}`, "error"); }
        return;
      }
      const command = input || await withUiDialog<string | undefined>(() => ctx.ui.input("SSH command:", lastCommand));
      if (!command) return;
      await connectInteractive(command, ctx);
    },
  });

  const multiServerToolNames = [
    "ssh_remote_control",
    "ssh_remote_read",
    "ssh_remote_write",
    "ssh_remote_edit",
    "ssh_remote_exec",
    "ssh_remote_batch",
    "ssh_remote_put",
    "ssh_remote_get",
    "ssh_remote_transfer",
    "ssh_remote_password",
  ];

  const ensureMultiServerToolsActive = () => {
    const available = new Set(pi.getAllTools().map((tool) => tool.name));
    const active = new Set(pi.getActiveTools());
    for (const name of multiServerToolNames) if (available.has(name)) active.add(name);
    pi.setActiveTools([...active]);
  };

  pi.on("session_start", async (event, ctx) => {
    currentCtx = ctx;
    resetUiDialogQueue();
    ensureMultiServerToolsActive();
    status(ctx);
    if (event.reason === "reload" && credentialCache.resume) {
      try { await reconnectRemote(); }
      catch (error) { ctx.ui.notify(`SSH remote automatic login after reload failed: ${(error as Error).message}`, "error"); }
    }
  });
  pi.on("session_shutdown", (event) => {
    // Any dialog still open dies with the session; never keep the queue waiting on it.
    resetUiDialogQueue();
    const previous = [...connections.values()];
    connections.clear();
    reconnectPromises.clear();
    // A connect parked on a discarded prompt must not block the endpoint forever.
    pendingConnects.clear();
    connectingLabels.clear();
    remote = null;
    routeRemoteTools = false;
    void stopForwards();
    for (const state of previous) state.client.end();
    if (event.reason !== "reload") credentialCache.resume = undefined;
  });
  pi.on("before_agent_start", (event) => {
    const config = loadRemoteConfig();
    const keys = Object.keys(config.endpoints ?? {});
    if (!keys.length) return undefined;
    // Give the model ground truth for *every* configured endpoint, not only the
    // live ones: most wrong-endpoint failures come from retyping an address.
    const known = keys.slice(0, 20).map((key) => {
      const note = config.endpoints?.[key]?.note?.trim();
      const cwd = connections.get(key)?.cwd ?? config.endpoints?.[key]?.remoteCwd;
      const flags = [connections.has(key) ? "connected" : "configured", cwd, note].filter(Boolean).join("; ");
      return `\n- ${key}${flags ? ` (${flags})` : ""}`;
    });
    const more = keys.length > known.length ? `\n- ...and ${keys.length - known.length} more` : "";
    const routing = remote && routeRemoteTools
      ? `Current working directory: ${remote.cwd} (via active SSH ${endpointDisplayLabel(remote)}). Built-in read, write, edit, and bash tools run on this active server; the user's \`!\`/\`!!\` commands always run locally on ${localCwd}.`
      : `Current working directory: ${localCwd}. Built-in tools and the user's \`!\` commands run locally.`;
    const systemPrompt = event.systemPrompt.replace(`Current working directory: ${localCwd}`, routing)
      + `\n\nSSH endpoints (exact keys; use one of these strings as the endpoint argument):${known.join("")}${more}\nCall ssh_remote_control action=endpoints if you need the current list again. Use ssh_remote_read, ssh_remote_write, ssh_remote_edit, ssh_remote_exec, or ssh_remote_batch with an explicit endpoint to operate on any configured server without switching the active workspace; a not-yet-connected endpoint is connected on demand. Prefer copying the exact key (including the username and port) instead of retyping an address. Use ssh_remote_control action activate to switch transparent built-in tool routing. Transfer files with ssh_remote_put (local→server), ssh_remote_get (server→local), or ssh_remote_transfer (server→server; relayed through this machine). Each accepts a single endpoint or a targets list for fan-out, handles directories recursively, and streams progress. When a remote step needs a password (remote sudo -S, another service, a jump host) and no prompt is available, decode the saved one for an endpoint with ssh_remote_password — treat the output as sensitive.`;
    return { systemPrompt };
  });
}
