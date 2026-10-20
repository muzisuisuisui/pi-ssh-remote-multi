/**
 * Offline regression test for the connect-time prompt layer.
 *
 * Two bugs motivate these checks:
 *   1. pi's interactive host only renders one extension dialog at a time and
 *      silently replaces the previous component. Parallel first-time connects
 *      therefore used to leave every prompt after the first unanswered forever,
 *      with the other connections stuck behind it.
 *   2. Every such prompt read exactly "SSH password:", so with several servers
 *      dialing at once there was no way to tell which one was asking.
 *
 * Needs no SSH connection and no TUI.
 */
import { passwordPromptText, pendingUiDialogCount, resetUiDialogQueue, withUiDialog } from "../index.ts";

let failures = 0;
const check = (label: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail ? ` (${detail})` : ""}`);
  if (!ok) failures += 1;
};

// ---- prompt text names the endpoint ---------------------------------------
const first = passwordPromptText("root@10.3.241.21:22");
const second = passwordPromptText("ubuntu@10.3.241.25:22");
check("prompt names the endpoint address", first.includes("root@10.3.241.21:22"), first);
check("parallel prompts for different hosts are distinguishable", first !== second && second.includes("ubuntu@10.3.241.25:22"));
check("prompt explains how to skip", /Esc/.test(first));

const retried = passwordPromptText("root@10.3.241.21:22", "saved password rejected");
check("retry prompt keeps the endpoint and says why it asked again", retried.includes("root@10.3.241.21:22") && retried.includes("saved password rejected"), retried);

const queued = passwordPromptText("root@10.3.241.21:22", undefined, 2);
check("prompt reports how many connections are waiting", queued.includes("2 more waiting"), queued);
check("no waiting note when nothing else is queued", !first.includes("waiting"), first);

// ---- dialogs are serialized, and none are lost ---------------------------
resetUiDialogQueue();
let active = 0;
let maxActive = 0;
const started: number[] = [];
const dialog = (index: number) => withUiDialog(async () => {
  active += 1;
  maxActive = Math.max(maxActive, active);
  started.push(index);
  await new Promise((resolve) => setTimeout(resolve, 5));
  active -= 1;
  return index;
});

const results = await Promise.all([dialog(0), dialog(1), dialog(2)]);
check("only one dialog occupies the prompt slot at a time", maxActive === 1, `max ${maxActive}`);
check("all three parallel connections get answered", results.join(",") === "0,1,2", results.join(","));
check("dialogs run in request order", started.join(",") === "0,1,2", started.join(","));
check("queue drains back to zero", pendingUiDialogCount() === 0, String(pendingUiDialogCount()));

// ---- a rejected dialog must not wedge the queue --------------------------
resetUiDialogQueue();
const order: string[] = [];
const failing = withUiDialog(async () => {
  order.push("first");
  throw new Error("dialog closed");
});
const failingHandled = failing.then(() => "resolved", (error: unknown) => `rejected:${(error as Error).message}`);
const following = withUiDialog(async () => {
  order.push("second");
  return "ok";
});
check("a rejected dialog still reports its error", (await failingHandled) === "rejected:dialog closed");
check("the next queued dialog runs after a rejection", (await following) === "ok" && order.join(",") === "first,second", order.join(","));
check("queue is empty again after a rejection", pendingUiDialogCount() === 0, String(pendingUiDialogCount()));

// ---- a queue that can never drain is recoverable -------------------------
resetUiDialogQueue();
const stuck = withUiDialog(() => new Promise<string>(() => { /* never resolves, like a dialog pi discarded */ }));
void stuck;
check("a stuck dialog counts as pending", pendingUiDialogCount() === 1, String(pendingUiDialogCount()));
resetUiDialogQueue();
const recovered = await withUiDialog(async () => "after-reset");
check("resetting the queue unblocks later prompts", recovered === "after-reset" && pendingUiDialogCount() === 0);

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
