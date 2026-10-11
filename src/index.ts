
 // AI Phone「角色电脑」——基于 @cloudflare/computer 的自部署 Worker。
 //
 // 普通版：Durable Object 持久化虚拟文件系统 + 内嵌 just-bash。
 // 可选：配置 worker_loaders 后，使用 Worker Shell 动态执行后端。
 // 不依赖 CloudflareContainerBackend，不启用真 Linux 容器。
 //
 // 安全模型：
 //  - 所有请求必须带 Authorization: Bearer <AGENT_TOKEN>；
 //  - workspace 名单字符集白名单，一个 workspace 一个 DO；
 //  - 路径禁止 ".."；输出与文件读取均有体积上限。

import { DurableObject } from "cloudflare:workers";
import {
  withWorkspace,
  getWorkspace,
  type DurableObjectStorageLike,
  type WorkspaceHandle,
} from "@cloudflare/computer";
import {
  WorkerShellBackend,
  WorkspaceFsAdapter,
  type WorkerShellLoader,
} from "@cloudflare/computer/backends/worker-shell";
import { WorkspaceServiceProxy } from "@cloudflare/computer";
import {
  Bash,
  NetworkAccessDeniedError,
  defineCommand,
  type SecureFetch,
} from "just-bash";

// Worker Shell 动态 Worker 的代理入口。
// 普通版不使用容器回环代理 WorkspaceProxy。
export { WorkspaceServiceProxy };

type Env = {
  Computer: DurableObjectNamespace;
  // 可选：worker_loaders 绑定。
  // 不配置时，使用内嵌 just-bash。
  LOADER?: WorkerShellLoader;
  AGENT_TOKEN?: string;
};

// cloudflare:workers 的 DurableObject 中 ctx/env 是 protected，
// withWorkspace 的选项工厂在类外运行，因此提供公开访问器。
class ComputerBase extends DurableObject<Env> {
  get doCtx() {
    return this.ctx;
  }

  get doEnv() {
    return this.env;
  }
}

// 普通版不再包装 withWorkspaceContainer，避免依赖容器后端。
export class Computer extends withWorkspace(
  ComputerBase,
  (self) => ({
    // workers-types 与包内类型的 SQL Row 泛型声明可能不同，
    // 运行时使用的是同一份 DO storage。
    storage: self.doCtx.storage as unknown as DurableObjectStorageLike,

    // 只有显式配置 LOADER 时才启用动态 Worker Shell。
    // 否则由 runShell() 降级至内嵌 just-bash。
    backends: self.doEnv.LOADER
      ? [
          new WorkerShellBackend({
            loader: self.doEnv.LOADER,
            workspace: {
              binding: "Computer",
              id: self.doCtx.id.toString(),
            },
            ctx: self.doCtx,
          }),
        ]
      : [],
  }),
) {}

// ── HTTP 层 ──

const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS,
    },
  });
}

function fail(error: string, status = 400): Response {
  return json({ ok: false, error }, status);
}

type ActionBody = {
  action?: string;
  /** 哪台电脑：char:<角色id> / workshop / 其他自定义。 */
  workspace?: string;
  path?: string;
  content?: string;
  base64?: string;
  command?: string;
  maxChars?: number;
};

const MAX_READ_CHARS = 200_000;
const MAX_WRITE_CHARS = 2_000_000;
const MAX_WRITE_B64 = 8_000_000;
const MAX_EXEC_OUTPUT = 60_000;

function cleanWorkspace(raw: unknown): string | null {
  const value = typeof raw === "string" ? raw.trim() : "";
  return /^[A-Za-z0-9:_-]{1,120}$/.test(value) ? value : null;
}

/** 绝对路径化，并禁止路径越级。 */
function cleanPath(raw: unknown, fallback = "/"): string {
  let value = typeof raw === "string" ? raw.trim() : "";

  if (!value) value = fallback;

  value = value.replace(/\u0000/g, "");

  if (!value.startsWith("/")) {
    value = `/${value}`;
  }

  const segments = value.split("/").filter(
    (segment) => segment && segment !== ".",
  );

  if (segments.includes("..")) {
    throw new Error("路径不能包含 ..");
  }

  return `/${segments.join("/")}`;
}

function parentDir(path: string): string {
  const index = path.lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }

  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64.replace(/\s/g, ""));
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ── 内嵌 Shell（普通版默认后端） ──
//
// 无需 Linux 容器，也不要求 worker_loaders。
// 文件系统通过 WorkspaceFsAdapter 对接同一个 Workspace。

const EMBEDDED_MAX_OUTPUT = 200_000;

const FETCH_TIMEOUT_MS = 20_000;
const FETCH_MAX_BYTES = 5 * 1024 * 1024;

const PRIVATE_HOST_RE =
  /^(localhost$|127\.|10\.|192\.168\.|169\.254\.|0\.|\[?::1\]?$|172\.(1[6-9]|2\d|3[01])\.)/i;

// 只读联网：仅 GET/HEAD，仅 HTTP(S)，禁止常见内网地址。
const readOnlyFetch: SecureFetch = async (url, options = {}) => {
  const method = (options.method || "GET").toUpperCase();

  if (method !== "GET" && method !== "HEAD") {
    throw new NetworkAccessDeniedError(url, "只允许 GET/HEAD");
  }

  const parsed = new URL(url);

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new NetworkAccessDeniedError(url, "仅支持 http/https");
  }

  if (PRIVATE_HOST_RE.test(parsed.hostname)) {
    throw new NetworkAccessDeniedError(url, "禁止访问内网地址");
  }

  const controller = new AbortController();
  const timeoutMs = Math.min(
    options.timeoutMs ?? FETCH_TIMEOUT_MS,
    FETCH_TIMEOUT_MS,
  );

  const timer = setTimeout(
    () => controller.abort(),
    timeoutMs,
  );

  try {
    const signal = options.signal
      ? AbortSignal.any([options.signal, controller.signal])
      : controller.signal;

    const res = await fetch(url, {
      method,
      headers: options.headers as HeadersInit | undefined,
      signal,
      redirect:
        options.followRedirects === false ? "manual" : "follow",
    });

    // 在读取前检查 Content-Length；读取后再检查实际大小。
    const contentLength = Number(res.headers.get("content-length") || 0);

    if (contentLength > FETCH_MAX_BYTES) {
      throw new Error("响应超过 5MB 上限");
    }

    const buffer = await res.arrayBuffer();

    if (buffer.byteLength > FETCH_MAX_BYTES) {
      throw new Error("响应超过 5MB 上限");
    }

    const headers: Record<string, string> = {};

    res.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      status: res.status,
      statusText: res.statusText,
      headers,
      body: new Uint8Array(buffer),
      url: res.url,
    };
  } finally {
    clearTimeout(timer);
  }
};

type ExecOutcome = {
  stdout: string;
  stderr: string;
  exitCode: number;
  engine: "isolate" | "embedded";
};

// 这里没有 Linux 内核，如实报告虚拟 Shell 环境。
const unameCommand = defineCommand("uname", async (args) => {
  const all = args.includes("-a");

  const stdout = all
    ? "FloatOS float-computer 1.0-embedded just-bash cloudflare-workers wasm32\n"
    : "FloatOS\n";

  return {
    stdout,
    stderr: "",
    exitCode: 0,
  };
});

async function runShell(
  ws: Awaited<ReturnType<typeof getWorkspace>>,
  command: string,
): Promise<ExecOutcome> {
  // 优先尝试已配置的动态 Worker Shell。
  try {
    using run = await ws.runtime.exec(command, {
      encoding: "utf8",
    });

    const { stdout, stderr, exitCode } = await run.result();

    return {
      stdout: typeof stdout === "string" ? stdout : "",
      stderr: typeof stderr === "string" ? stderr : "",
      exitCode: exitCode ?? 0,
      engine: "isolate",
    };
  } catch (err) {
    const message =
      err instanceof Error ? err.message : String(err);

    // 没有执行后端时，降级到内嵌 Shell。
    if (!/execution backend/i.test(message)) {
      throw err;
    }
  }

  const bash = new Bash({
    fs: new WorkspaceFsAdapter(ws.fs as never) as never,
    cwd: "/",
    fetch: readOnlyFetch,
    defenseInDepth: {
      enabled: false,
    },
    executionLimits: {
      maxOutputSize: EMBEDDED_MAX_OUTPUT,
    },
    customCommands: [unameCommand],
  });

  const result = await bash.exec(command);

  return {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exitCode,
    engine: "embedded",
  };
}

// ── Worker 入口 ──

export default {
  async fetch(
    request: Request,
    env: Env,
  ): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS,
      });
    }

    if (request.method !== "POST") {
      return fail("只接受 POST", 405);
    }

    const expected = env.AGENT_TOKEN?.trim();

    if (!expected) {
      return fail("服务端未配置 AGENT_TOKEN", 503);
    }

    if (
      request.headers.get("authorization") !==
      `Bearer ${expected}`
    ) {
      return fail("密钥不正确", 401);
    }

    let body: ActionBody;

    try {
      body = await request.json() as ActionBody;
    } catch {
      return fail("请求体不是合法 JSON");
    }

    const workspace = cleanWorkspace(body.workspace);

    if (!workspace) {
      return fail(
        "workspace 不合法（字母/数字/冒号/横线/下划线，≤120 字符）",
      );
    }

    const stub = env.Computer.get(
      env.Computer.idFromName(`ws/${workspace}`),
    );

    try {
      using ws = await getWorkspace(
        stub as unknown as WorkspaceHandle,
      );

      switch (body.action) {
        case "status": {
          // 文件系统探活。
          await ws.fs.mkdir("/", {
            recursive: true,
          }).catch(() => {});

          let shell = false;
          let engine: string | undefined;
          let linux = false;

          try {
            const probe = await runShell(ws, "echo ok");

            shell = probe.exitCode === 0;
            engine = probe.engine;

            if (shell) {
              const uname = await runShell(ws, "uname")
                .catch(() => null);

              linux = uname
                ? /\bLinux\b/.test(uname.stdout)
                : false;
            }
          } catch {
            // Shell 不可用时仍报告文件系统状态。
          }

          const mode = !shell
            ? "fs-only"
            : linux
              ? "container"
              : "shell";

          return json({
            ok: true,
            fs: true,
            shell,
            mode,
            engine: linux ? "container" : engine,
          });
        }

        case "list": {
          const path = cleanPath(body.path);
          const entries = await ws.fs.readdir(path);

          return json({
            ok: true,
            path,
            entries: entries.map((entry) => ({
              name: entry.name,
              dir: Boolean(entry.isDirectory),
            })),
          });
        }

        case "read": {
          const path = cleanPath(body.path);

          if (path === "/") {
            return fail("请指定文件路径");
          }

          const maxChars = Math.max(
            1,
            Math.min(
              MAX_READ_CHARS,
              Number(body.maxChars) || MAX_READ_CHARS,
            ),
          );

          const content = await ws.fs.readFile(path, "utf8");
          const truncated = content.length > maxChars;

          return json({
            ok: true,
            path,
            content: truncated
              ? content.slice(0, maxChars)
              : content,
            truncated,
          });
        }

        case "read_base64": {
          const path = cleanPath(body.path);

          if (path === "/") {
            return fail("请指定文件路径");
          }

          const stream = await ws.fs.readFile(path);
          const buffer = await new Response(
            stream as ReadableStream,
          ).arrayBuffer();

          if (buffer.byteLength > MAX_WRITE_B64) {
            return fail(
              "文件太大，无法经此接口传输（≤6MB）",
            );
          }

          return json({
            ok: true,
            path,
            base64: toBase64(new Uint8Array(buffer)),
          });
        }

        case "write": {
          const path = cleanPath(body.path);

          if (path === "/") {
            return fail("请指定文件路径");
          }

          await ws.fs.mkdir(parentDir(path), {
            recursive: true,
          }).catch(() => {});

          if (typeof body.base64 === "string") {
            if (body.base64.length > MAX_WRITE_B64) {
              return fail("内容超限（base64 ≤8MB）");
            }

            await ws.fs.writeFile(
              path,
              fromBase64(body.base64),
            );
          } else {
            const content =
              typeof body.content === "string"
                ? body.content
                : "";

            if (content.length > MAX_WRITE_CHARS) {
              return fail("内容超限（文本 ≤2MB）");
            }

            await ws.fs.writeFile(path, content);
          }

          return json({
            ok: true,
            path,
          });
        }

        case "mkdir": {
          const path = cleanPath(body.path);

          await ws.fs.mkdir(path, {
            recursive: true,
          });

          return json({
            ok: true,
            path,
          });
        }

        case "delete": {
          const path = cleanPath(body.path);

          if (path === "/") {
            return fail("不能删除根目录");
          }

          await ws.fs.rm(path, {
            recursive: true,
          });

          return json({
            ok: true,
            path,
          });
        }

        case "exec": {
          const command =
            typeof body.command === "string"
              ? body.command.trim()
              : "";

          if (!command) {
            return fail("缺少 command");
          }

          if (command.length > 4000) {
            return fail("命令过长");
          }

          try {
            const result = await runShell(ws, command);

            const clip = (value: string) =>
              value.length > MAX_EXEC_OUTPUT
                ? `${value.slice(0, MAX_EXEC_OUTPUT)}\n…（输出过长已截断）`
                : value;

            return json({
              ok: true,
              exitCode: result.exitCode,
              stdout: clip(result.stdout),
              stderr: clip(result.stderr),
              engine: result.engine,
            });
          } catch (err) {
            return fail(
              `shell 不可用或执行失败：${
                err instanceof Error
                  ? err.message
                  : String(err)
              }`,
              501,
            );
          }
        }

        default:
          return fail(
            "未知 action（status/list/read/read_base64/write/mkdir/delete/exec）",
          );
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err);

      if (/ENOENT|not found|no such/i.test(message)) {
        return fail(
          `文件或目录不存在（${message}）`,
          404,
        );
      }

      return fail(`操作失败：${message}`, 502);
    }
  },
} satisfies ExportedHandler<Env>;
