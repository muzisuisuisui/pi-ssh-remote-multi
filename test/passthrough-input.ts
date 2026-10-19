/**
 * Offline regression test for the `$` passthrough input routing.
 *
 * Covers the decisions that are easy to break by accident: `!` is no longer
 * intercepted, `$` is claimed only for leading-dollar interactive text, and a
 * missing/unconnected target fails closed with a notify instead of leaking the
 * text into the model context. Needs no SSH connection.
 */
import sshRemote from "../index.ts";

const handlers = new Map<string, Function>();
const commands = new Map<string, any>();
const notices: Array<{ msg: string; level?: string }> = [];
const statuses = new Map<string, string | undefined>();

const pi: any = {
  on: (name: string, handler: Function) => { handlers.set(name, handler); },
  registerTool: () => {},
  registerCommand: (name: string, options: any) => { commands.set(name, options); },
  registerEntryRenderer: () => {},
  getAllTools: () => [],
  getActiveTools: () => [],
  setActiveTools: () => {},
  appendEntry: () => {},
};
sshRemote(pi);

const ctx: any = {
  mode: "print",
  cwd: process.cwd(),
  ui: {
    notify: (msg: string, level?: string) => { notices.push({ msg, level }); },
    setStatus: (key: string, value: string | undefined) => { statuses.set(key, value); },
    select: async () => undefined,
    input: async () => undefined,
    confirm: async () => false,
    custom: async () => undefined,
    theme: { fg: (_color: string, text: string) => text, bold: (text: string) => text },
  },
};

let failures = 0;
const check = (label: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail ? ` (${detail})` : ""}`);
  if (!ok) failures += 1;
};

const input = handlers.get("input");
check("input handler registered", typeof input === "function");
check("`!` is no longer intercepted (user_bash hook removed)", !handlers.has("user_bash"));
check("/control_ssh registered", commands.has("control_ssh"));

const feed = async (text: string, extra: Record<string, unknown> = {}) => (input! as Function)(
  { type: "input", text, source: "interactive", ...extra },
  ctx,
);

for (const [label, text] of [
  ["plain chat", "hello there"],
  ["dollar amount", "$100 是多少钱"],
  ["attached images", "$ls"],
] as const) {
  const result = await feed(text, label === "attached images" ? { images: [{ type: "text", text: "x" }] } : {});
  check(`${label} passes through to the model`, (result as any).action === "continue", JSON.stringify(result));
}

for (const [label, text] of [
  ["bare $ help", "$"],
  ["remote command", "$ls /tmp"],
  ["$cd", "$cd /tmp"],
  ["$ctx <selector>", "$ctx 21"],
] as const) {
  notices.length = 0;
  const result = await feed(text);
  const handled = (result as any).action === "handled";
  check(`${label} handled without touching the model`, handled, JSON.stringify(result));
  check(`${label} reported something to the user`, notices.length > 0, notices[0]?.level ?? "none");
}

// With no endpoint configured at all, `$` must fail closed with an error, not silently continue.
notices.length = 0;
await feed("$hostname");
check("no-connection $ command reports an error", notices[0]?.level === "error", notices[0]?.msg.slice(0, 40));

await handlers.get("session_start")!({ reason: "start" }, ctx);
check("footer status cleared with zero connections", statuses.get("ssh-passthrough") === undefined,
  String(statuses.get("ssh-passthrough")));

notices.length = 0;
await commands.get("control_ssh")!.handler("", ctx);
check("/control_ssh without connections explains itself", notices[0]?.level === "error", notices[0]?.msg.slice(0, 40));

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
