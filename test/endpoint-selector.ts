/**
 * Offline checks for endpoint selector resolution.
 *
 * The agent cannot copy endpoint keys out of a terminal buffer, so most
 * "endpoint not found" failures come from a slightly different but still
 * unambiguous spelling (`root@IP`, `IP:22`, a note, or the last IP octet).
 * These cases must resolve; genuinely ambiguous ones must report candidates
 * instead of silently picking a server.
 */
import assert from "node:assert/strict";
import { describeEndpointResolutionFailure, endpointSelectorMatches, normalizeEndpointSelector } from "../index.ts";

const ENDPOINTS = {
  "y00584608@110.3.241.15:22": { note: ".15 work15 8x910B1" },
  "l00567503@110.3.241.16:22": { note: ".16 master" },
  "z00525195@110.3.241.21:22": { note: ".21 dsv41-a2 running" },
  "z00525195@110.3.241.25:22": { note: ".25 host25" },
  "root@141.61.33.153:22": { note: "A5 Ascend950PR" },
};
const KEYS = Object.keys(ENDPOINTS);
const resolve = (requested: string) => endpointSelectorMatches(KEYS, ENDPOINTS, requested);

let failed = 0;
const check = (name: string, run: () => void) => {
  try { run(); console.log(`ok   ${name}`); }
  catch (error) { failed += 1; console.log(`FAIL ${name}: ${(error as Error).message}`); }
};

check("exact key", () => assert.deepEqual(resolve("z00525195@110.3.241.21:22"), ["z00525195@110.3.241.21:22"]));
check("bare host/IP", () => assert.deepEqual(resolve("110.3.241.25"), ["z00525195@110.3.241.25:22"]));
check("host:port", () => assert.deepEqual(resolve("110.3.241.15:22"), ["y00584608@110.3.241.15:22"]));
check("user@host", () => assert.deepEqual(resolve("z00525195@110.3.241.21"), ["z00525195@110.3.241.21:22"]));
check("wrong username, right address", () => assert.deepEqual(resolve("root@110.3.241.25:22"), ["z00525195@110.3.241.25:22"]));
check("wrong username, no port", () => assert.deepEqual(resolve("root@110.3.241.16"), ["l00567503@110.3.241.16:22"]));
check("ssh command with -p", () => assert.deepEqual(resolve("ssh root@110.3.241.21 -p 22"), ["z00525195@110.3.241.21:22"]));
check("quoted key", () => assert.deepEqual(resolve('"z00525195@110.3.241.21:22"'), ["z00525195@110.3.241.21:22"]));
check("note token", () => assert.deepEqual(resolve("work15"), ["y00584608@110.3.241.15:22"]));
check("note with leading dot", () => assert.deepEqual(resolve(".16"), ["l00567503@110.3.241.16:22"]));
check("trailing octet", () => assert.deepEqual(resolve("21"), ["z00525195@110.3.241.21:22"]));
check("prefix of key", () => assert.deepEqual(resolve("y00584608"), ["y00584608@110.3.241.15:22"]));
check("ambiguous octet lists both", () => assert.equal(resolve("1").length > 1, true));
check("unknown address stays unresolved", () => assert.deepEqual(resolve("10.9.9.9"), []));

check("normalize strips ssh decoration", () => {
  assert.equal(normalizeEndpointSelector("  ssh  root@10.0.0.1 -p 2202  "), "root@10.0.0.1");
});
check("failure lists every endpoint and marks connectivity", () => {
  const message = describeEndpointResolutionFailure(
    "10.9.9.9", KEYS, ENDPOINTS, new Set(["z00525195@110.3.241.21:22"]), false,
  );
  assert.match(message, /Endpoint not found: "10\.9\.9\.9"/);
  for (const key of KEYS) assert.ok(message.includes(key), `missing ${key}`);
  assert.match(message, /z00525195@110\.3\.241\.21:22 {2}\(connected; \.21/);
  assert.match(message, /l00567503@110\.3\.241\.16:22 {2}\(configured; \.16/);
  assert.match(message, /ssh_remote_control action=connect/);
});
check("ambiguous failure names the candidates", () => {
  const message = describeEndpointResolutionFailure(
    "1", KEYS, ENDPOINTS, new Set(), false, resolve("1"),
  );
  assert.match(message, /ambiguous/i);
  for (const key of resolve("1")) assert.ok(message.includes(key));
});
check("connected-only failure explains how to reconnect", () => {
  const message = describeEndpointResolutionFailure(
    "10.9.9.9", KEYS, ENDPOINTS, new Set(), true,
  );
  assert.match(message, /not connected/);
  assert.match(message, /action=connect or action=reconnect/);
});

if (failed) {
  console.error(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log("\nall endpoint selector checks passed");
