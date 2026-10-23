/**
 * Offline regression test for the transfer guards.
 *
 * `ssh_remote_put` used to hang forever now and then: ssh2's `fastPut`/`fastGet`
 * never invoke their final callback when the peer stops answering mid-file, and
 * pending SFTP requests on a dead channel never settle either. These checks pin
 * the behaviour that replaced "hang": a stall watchdog, abort support, channel
 * death surfacing as an error, and a progress callback that cannot break a
 * transfer.
 *
 * Uses fake SFTP wrappers, so no server and no network are involved.
 */
import {
  SFTP_STALL_TIMEOUT_MS,
  isReconnectable,
  sftpFastXfer,
  withSftp,
} from "../index.ts";

let failures = 0;
const check = (label: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail ? ` (${detail})` : ""}`);
  if (!ok) failures += 1;
};

interface FakeSftp {
  destroyed: number;
  calls: string[];
  fastPut?: (src: string, dst: string, opts: any, cb: (error?: Error | null) => void) => void;
  fastGet?: (src: string, dst: string, opts: any, cb: (error?: Error | null) => void) => void;
  destroy: () => void;
}

const makeSftp = (impl: Partial<FakeSftp> = {}): FakeSftp => {
  const fake: FakeSftp = {
    destroyed: 0,
    calls: [],
    destroy: () => { fake.destroyed += 1; },
    ...impl,
  };
  if (!fake.fastPut) {
    fake.fastPut = function (this: unknown, _src: string, _dst: string, opts: any, cb: (error?: Error | null) => void) {
      fake.calls.push("fastPut");
      // Behave like a healthy peer: report progress, then finish.
      opts.step?.(opts.fileSize, opts.step);
      cb(null);
    };
  }
  if (!fake.fastGet) {
    fake.fastGet = function (this: unknown, _src: string, _dst: string, opts: any, cb: (error?: Error | null) => void) {
      fake.calls.push("fastGet");
      opts.step?.(opts.fileSize);
      cb(null);
    };
  }
  return fake;
};

const asSftp = (fake: FakeSftp) => fake as unknown as Parameters<typeof sftpFastXfer>[1];

// ---- happy path -----------------------------------------------------------
{
  const fake = makeSftp();
  let lastDone = -1;
  await sftpFastXfer("upload", asSftp(fake), "/local/a.bin", "/remote/a.bin", 1024, { concurrency: 8, chunkSize: 4096 },
    (done) => { lastDone = done; });
  check("upload resolves when the peer finishes", fake.calls.join(",") === "fastPut" && lastDone === 1024, `${fake.calls.join(",")}/${lastDone}`);
  check("a completed transfer leaves the channel alone", fake.destroyed === 0);
  check("default stall timeout is minutes, not milliseconds", SFTP_STALL_TIMEOUT_MS >= 60_000, String(SFTP_STALL_TIMEOUT_MS));
}

{
  const fake = makeSftp();
  await sftpFastXfer("download", asSftp(fake), "/remote/a.bin", "/local/a.bin", 10, { concurrency: 4, chunkSize: 4096 }, () => {});
  check("download uses fastGet (not fastPut)", fake.calls.join(",") === "fastGet", fake.calls.join(","));
}

// ---- peer reports an error ------------------------------------------------
{
  const fake = makeSftp({
    fastPut: (_src, _dst, _opts, cb) => { setTimeout(() => cb(new Error("permission denied")), 1); },
  });
  const error = await sftpFastXfer("upload", asSftp(fake), "/l", "/r", 16, { concurrency: 1, chunkSize: 4096 }, () => {})
    .then(() => undefined, (reason: unknown) => (reason as Error).message);
  check("peer errors surface unchanged", error === "permission denied", String(error));
}

// ---- a stalled transfer must fail instead of hanging ----------------------
{
  // Like a dropped connection: the transfer starts, then no callback, no step.
  const fake = makeSftp({ fastPut: () => { /* never calls back */ } });
  const started = Date.now();
  const error = await sftpFastXfer("upload", asSftp(fake), "/l", "/r", 5 * 1024 * 1024, { concurrency: 8, chunkSize: 32768, stallTimeoutMs: 60 }, () => {})
    .then(() => undefined, (reason: unknown) => (reason as Error).message);
  const elapsed = Date.now() - started;
  check("stalled upload rejects instead of hanging", typeof error === "string" && /stalled/.test(error), String(error));
  check("stall message is actionable", /no data moved/.test(String(error)) && /retry/.test(String(error)), String(error));
  check("stall fires near the configured timeout", elapsed >= 50 && elapsed < 2000, `${elapsed}ms`);
  check("stalled transfer frees the channel", fake.destroyed === 1, String(fake.destroyed));
}

{
  // Slow but alive: progress keeps resetting the watchdog.
  const fake = makeSftp({
    fastPut: (_src, _dst, opts, cb) => {
      let sent = 0;
      const timer = setInterval(() => {
        sent += 1;
        opts.step(sent * 1000);
        if (sent < 5) return;
        clearInterval(timer);
        cb(null);
      }, 40);
    },
  });
  const outcome = await sftpFastXfer("upload", asSftp(fake), "/l", "/r", 5000, { concurrency: 2, chunkSize: 1000, stallTimeoutMs: 120 }, () => {})
    .then(() => "ok", (reason: unknown) => `failed: ${(reason as Error).message}`);
  check("steady progress is not mistaken for a stall", outcome === "ok", outcome);
}

// ---- abort support --------------------------------------------------------
{
  const fake = makeSftp({ fastPut: () => { /* ignores everything */ } });
  const controller = new AbortController();
  const promise = sftpFastXfer("upload", asSftp(fake), "/l", "/r", 1024, { concurrency: 1, chunkSize: 1024, stallTimeoutMs: 5000, signal: controller.signal }, () => {});
  setTimeout(() => controller.abort(), 20);
  const error = await promise.then(() => undefined, (reason: unknown) => (reason as Error).message);
  check("aborting a transfer rejects promptly", error === "Transfer aborted", String(error));
  check("aborting frees the channel", fake.destroyed === 1, String(fake.destroyed));
}

{
  const fake = makeSftp();
  const controller = new AbortController();
  controller.abort();
  const error = await sftpFastXfer("upload", asSftp(fake), "/l", "/r", 1024, { concurrency: 1, chunkSize: 1024, signal: controller.signal }, () => {})
    .then(() => undefined, (reason: unknown) => (reason as Error).message);
  check("an already-aborted signal never starts the transfer", error === "Transfer aborted" && fake.calls.length === 0, `${error}/${fake.calls.join(",")}`);
}

// ---- a throwing progress callback must not break the transfer -------------
{
  const fake = makeSftp();
  const outcome = await sftpFastXfer("upload", asSftp(fake), "/l", "/r", 2048, { concurrency: 2, chunkSize: 1024, stallTimeoutMs: 200 }, () => {
    throw new Error("the UI callback exploded");
  }).then(() => "ok", (reason: unknown) => `failed: ${(reason as Error).message}`);
  check("a throwing progress callback cannot fail the upload", outcome === "ok", outcome);
}

// ---- a dead channel rejects instead of waiting forever -------------------
{
  const listeners = new Map<string, Array<(...args: any[]) => void>>();
  const channel: any = {
    ended: 0,
    once(event: string, handler: (...args: any[]) => void) {
      const list = listeners.get(event) ?? [];
      list.push(handler);
      listeners.set(event, list);
      return channel;
    },
    end() { channel.ended += 1; },
    destroy() {},
  };
  const client: any = { sftp: (cb: (error: Error | null, sftp: any) => void) => { setTimeout(() => cb(null, channel), 1); return client; } };

  const operation = withSftp(client, () => new Promise<void>(() => { /* like a stat that never calls back */ }));
  setTimeout(() => {
    for (const handler of listeners.get("close") ?? []) handler();
  }, 30);
  const error = await operation.then(() => undefined, (reason: unknown) => (reason as Error).message);
  check("a closed SFTP channel rejects pending operations", /closed/i.test(String(error)), String(error));
  check("the channel is closed afterwards", channel.ended >= 1, String(channel.ended));
}

{
  const listeners = new Map<string, Array<(...args: any[]) => void>>();
  const channel: any = {
    ended: 0,
    once(event: string, handler: (...args: any[]) => void) {
      const list = listeners.get(event) ?? [];
      list.push(handler);
      listeners.set(event, list);
      return channel;
    },
    end() { channel.ended += 1; },
    destroy() {},
  };
  const client: any = { sftp: (cb: (error: Error | null, sftp: any) => void) => { setTimeout(() => cb(null, channel), 1); return client; } };
  const result = await withSftp(client, async () => "done");
  check("a healthy operation still returns its value", result === "done");
  check("the channel is closed after a healthy operation", channel.ended === 1, String(channel.ended));
}

// ---- which failures deserve one automatic reconnect + retry --------------
for (const [label, message, expected] of [
  ["dropped link (ssh2 wording)", "Received unexpected SFTP session termination", true],
  ["dead channel", "SFTP channel closed during the operation", true],
  ["socket reset", "read ECONNRESET", true],
  ["drop while opening the SFTP subsystem", "Unable to start subsystem: sftp", true],
  ["not connected", "Client is not connected", true],
  ["stalled transfer", "upload stalled: no data moved for 120s (5.0MB total).", false],
  ["user abort", "Transfer aborted", false],
  ["remote permission error", "Permission denied", false],
  ["connection aborted (ECONNABORTED)", "connection aborted", true],
] as const) {
  check(`reconnect decision: ${label} -> ${expected ? "retry" : "surface"}`, isReconnectable(new Error(message)) === expected, message);
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
