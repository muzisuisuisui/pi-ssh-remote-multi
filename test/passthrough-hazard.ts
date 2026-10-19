/**
 * Offline unit test for the `$` interactive-command classifier.
 *
 * The `$` channel streams remote output back but never writes to the remote
 * stdin, so anything that waits for its next input would hang until the timeout.
 * Blocking the wrong command is a nuisance; blocking a working one (the
 * `docker exec ... bash -lc '...'` form) is much worse, so both directions are
 * pinned here.
 */
import { interactiveHazard } from "../index.ts";

let failures = 0;
const expect = (command: string, shouldBlock: boolean) => {
  const hazard = interactiveHazard(command);
  const ok = (hazard !== undefined) === shouldBlock;
  if (!ok) failures += 1;
  console.log(`${ok ? "ok  " : "FAIL"} ${shouldBlock ? "拦截" : "放行"}  ${JSON.stringify(command)}${hazard ? `   <- ${hazard}` : ""}`);
};

console.log("--- 必须拦截（会永远等键盘） ---");
expect("su - root", true);
expect("sudo su - root", true);
expect("docker exec -it QWEN-9B bash", true);
expect("docker exec -i QWEN-9B sh", true);
expect("docker exec -it QWEN-9B", true);
expect("bash", true);
expect("vim", true);
expect("vim notes.md", true);
expect("top", true);
expect("htop", true);
expect("python", true);
expect("ssh 10.0.0.1", true);
expect("ssh -p 22 10.0.0.1", true);
expect("ssh -o StrictHostKeyChecking=no 10.0.0.1", true);
expect("less /var/log/messages", true);
expect("cd /home && bash", true);

console.log("--- 必须放行（单发型，含常用容器写法） ---");
expect("docker exec QWEN-9B bash -lc 'nvidia-smi'", false);
expect("docker exec -it QWEN-9B bash -lc 'ps -ef'", false);
expect("docker exec -w /tmp QWEN-9B sh -c 'pwd'", false);
expect("docker ps", false);
expect("nvidia-smi", false);
expect("ls -la", false);
expect("python -c 'print(1)'", false);
expect("python train.py", false);
expect("bash -lc 'echo hi'", false);
expect("bash script.sh", false);
expect("ssh 10.0.0.1 hostname", false);
expect("ssh -p 22 10.0.0.1 hostname", false);
expect("sudo -n systemctl status npu-smi", false);
expect("echo $HOME", false);
expect("ps -ef | grep python", false);
expect("cd /tmp && pwd", false);

console.log(failures ? `\n${failures} case(s) wrong` : "\nall hazard cases ok");
process.exit(failures ? 1 : 0);
