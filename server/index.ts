import express from "express";
import cors from "cors";
import path from "path";
import fs from "node:fs";
import os from "node:os";
import { randomUUID, createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { spawn, execFile, execFileSync, type ChildProcess } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { WebSocketServer, WebSocket } from "ws";
import { fileURLToPath } from "node:url";
import type { IncomingMessage } from "node:http";

// ---------------------------------------------------------------------------
// .env loader (no dotenv dependency)
// ---------------------------------------------------------------------------
const __server_dirname = path.dirname(fileURLToPath(import.meta.url));
const envFilePath = path.resolve(__server_dirname, "..", ".env");
try {
  if (fs.existsSync(envFilePath)) {
    const envContent = fs.readFileSync(envFilePath, "utf8");
    for (const line of envContent.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const value = trimmed.slice(eqIdx + 1).trim();
      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }
  }
} catch { /* ignore .env read errors */ }

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PKG_VERSION: string = (() => {
  try {
    return JSON.parse(
      fs.readFileSync(path.resolve(__server_dirname, "..", "package.json"), "utf8"),
    ).version ?? "1.0.0";
  } catch {
    return "1.0.0";
  }
})();

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "127.0.0.1";

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ---------------------------------------------------------------------------
// OAuth encryption helpers
// ---------------------------------------------------------------------------
const OAUTH_ENCRYPTION_SECRET =
  process.env.OAUTH_ENCRYPTION_SECRET || process.env.SESSION_SECRET || "";

function oauthEncryptionKey(): Buffer {
  if (!OAUTH_ENCRYPTION_SECRET) {
    throw new Error("Missing OAUTH_ENCRYPTION_SECRET");
  }
  return createHash("sha256").update(OAUTH_ENCRYPTION_SECRET, "utf8").digest();
}

function encryptSecret(plaintext: string): string {
  const key = oauthEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", iv.toString("base64"), tag.toString("base64"), enc.toString("base64")].join(":");
}

function decryptSecret(payload: string): string {
  const [ver, ivB64, tagB64, ctB64] = payload.split(":");
  if (ver !== "v1" || !ivB64 || !tagB64 || !ctB64) throw new Error("invalid_encrypted_payload");
  const key = oauthEncryptionKey();
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const ct = Buffer.from(ctB64, "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ct), decipher.final()]);
  return dec.toString("utf8");
}

// ---------------------------------------------------------------------------
// OAuth web-auth constants & PKCE helpers
// ---------------------------------------------------------------------------
const OAUTH_BASE_URL = process.env.OAUTH_BASE_URL || `http://${HOST}:${PORT}`;

const OAUTH_GITHUB_CLIENT_ID = process.env.OAUTH_GITHUB_CLIENT_ID || "";
const OAUTH_GITHUB_CLIENT_SECRET = process.env.OAUTH_GITHUB_CLIENT_SECRET || "";
const OAUTH_GOOGLE_CLIENT_ID = process.env.OAUTH_GOOGLE_CLIENT_ID || "";
const OAUTH_GOOGLE_CLIENT_SECRET = process.env.OAUTH_GOOGLE_CLIENT_SECRET || "";

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function pkceVerifier(): string {
  return b64url(randomBytes(32));
}

async function pkceChallengeS256(verifier: string): Promise<string> {
  return b64url(createHash("sha256").update(verifier, "ascii").digest());
}

// ---------------------------------------------------------------------------
// OAuth helper functions
// ---------------------------------------------------------------------------
function sanitizeOAuthRedirect(raw: string | undefined): string {
  if (!raw) return "/";
  try {
    const u = new URL(raw);
    if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return raw;
  } catch { /* not absolute URL — treat as path */ }
  if (raw.startsWith("/")) return raw;
  return "/";
}

function appendOAuthQuery(url: string, key: string, val: string): string {
  const u = new URL(url);
  u.searchParams.set(key, val);
  return u.toString();
}

// ---------------------------------------------------------------------------
// Production static file serving
// ---------------------------------------------------------------------------
const distDir = path.resolve(__server_dirname, "..", "dist");
const isProduction = !process.env.VITE_DEV && fs.existsSync(path.join(distDir, "index.html"));

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const dbPath = process.env.DB_PATH ?? path.join(process.cwd(), "climpire.sqlite");
const db = new DatabaseSync(dbPath);
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA busy_timeout = 3000");

const logsDir = process.env.LOGS_DIR ?? path.join(process.cwd(), "logs");
try {
  fs.mkdirSync(logsDir, { recursive: true });
} catch { /* ignore */ }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function nowMs(): number {
  return Date.now();
}

function firstQueryValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const first = value.find((item) => typeof item === "string");
    return typeof first === "string" ? first : undefined;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Schema creation
// ---------------------------------------------------------------------------
db.exec(`
CREATE TABLE IF NOT EXISTS departments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_ko TEXT NOT NULL,
  icon TEXT NOT NULL,
  color TEXT NOT NULL,
  description TEXT,
  sort_order INTEGER NOT NULL DEFAULT 99,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_ko TEXT NOT NULL,
  department_id TEXT REFERENCES departments(id),
  role TEXT NOT NULL CHECK(role IN ('team_leader','senior','junior','intern')),
  cli_provider TEXT CHECK(cli_provider IN ('claude','codex','gemini','opencode','copilot','antigravity')),
  avatar_emoji TEXT NOT NULL DEFAULT '🤖',
  personality TEXT,
  status TEXT NOT NULL DEFAULT 'idle' CHECK(status IN ('idle','working','break','offline')),
  current_task_id TEXT,
  stats_tasks_done INTEGER DEFAULT 0,
  stats_xp INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  department_id TEXT REFERENCES departments(id),
  assigned_agent_id TEXT REFERENCES agents(id),
  status TEXT NOT NULL DEFAULT 'inbox' CHECK(status IN ('inbox','planned','in_progress','review','done','cancelled')),
  priority INTEGER DEFAULT 0,
  task_type TEXT DEFAULT 'general' CHECK(task_type IN ('general','development','design','analysis','presentation','documentation')),
  project_path TEXT,
  result TEXT,
  started_at INTEGER,
  completed_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()*1000),
  updated_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  sender_type TEXT NOT NULL CHECK(sender_type IN ('ceo','agent','system')),
  sender_id TEXT,
  receiver_type TEXT NOT NULL CHECK(receiver_type IN ('agent','department','all')),
  receiver_id TEXT,
  content TEXT NOT NULL,
  message_type TEXT DEFAULT 'chat' CHECK(message_type IN ('chat','task_assign','announcement','report','status_update')),
  task_id TEXT REFERENCES tasks(id),
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS task_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT REFERENCES tasks(id),
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_credentials (
  provider TEXT PRIMARY KEY,
  source TEXT,
  encrypted_data TEXT NOT NULL,
  email TEXT,
  scope TEXT,
  expires_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()*1000),
  updated_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS oauth_states (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  verifier_enc TEXT NOT NULL,
  redirect_to TEXT
);

CREATE TABLE IF NOT EXISTS cli_usage_cache (
  provider TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(assigned_agent_id);
CREATE INDEX IF NOT EXISTS idx_tasks_dept ON tasks(department_id);
CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_type, receiver_id, created_at DESC);
`);

// Add columns to oauth_credentials for web-oauth tokens (safe to run repeatedly)
try { db.exec("ALTER TABLE oauth_credentials ADD COLUMN access_token_enc TEXT"); } catch { /* already exists */ }
try { db.exec("ALTER TABLE oauth_credentials ADD COLUMN refresh_token_enc TEXT"); } catch { /* already exists */ }

// ---------------------------------------------------------------------------
// Seed default data
// ---------------------------------------------------------------------------
const deptCount = (db.prepare("SELECT COUNT(*) as cnt FROM departments").get() as { cnt: number }).cnt;

if (deptCount === 0) {
  const insertDept = db.prepare(
    "INSERT INTO departments (id, name, name_ko, icon, color, sort_order) VALUES (?, ?, ?, ?, ?, ?)"
  );
  // Workflow order: 기획 → 개발 → 디자인 → QA → 인프라보안 → 운영
  insertDept.run("planning",  "Planning",    "기획팀",     "📊", "#f59e0b", 1);
  insertDept.run("dev",       "Development", "개발팀",     "💻", "#3b82f6", 2);
  insertDept.run("design",    "Design",      "디자인팀",   "🎨", "#8b5cf6", 3);
  insertDept.run("qa",        "QA/QC",       "품질관리팀", "🔍", "#ef4444", 4);
  insertDept.run("devsecops", "DevSecOps",   "인프라보안팀","🛡️", "#f97316", 5);
  insertDept.run("operations","Operations",  "운영팀",     "⚙️", "#10b981", 6);
  console.log("[CLImpire] Seeded default departments");
}

const agentCount = (db.prepare("SELECT COUNT(*) as cnt FROM agents").get() as { cnt: number }).cnt;

if (agentCount === 0) {
  const insertAgent = db.prepare(
    `INSERT INTO agents (id, name, name_ko, department_id, role, cli_provider, avatar_emoji, personality)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  // Development (3)
  insertAgent.run(randomUUID(), "Aria",  "아리아", "dev",        "team_leader", "claude",   "👩‍💻", "꼼꼼한 시니어 개발자");
  insertAgent.run(randomUUID(), "Bolt",  "볼트",   "dev",        "senior",      "codex",    "⚡",   "빠른 코딩 전문가");
  insertAgent.run(randomUUID(), "Nova",  "노바",   "dev",        "junior",      "copilot",  "🌟",   "창의적인 주니어");
  // Design (2)
  insertAgent.run(randomUUID(), "Pixel", "픽셀",   "design",     "team_leader", "claude",   "🎨",   "디자인 리더");
  insertAgent.run(randomUUID(), "Luna",  "루나",   "design",     "junior",      "gemini",   "🌙",   "감성적인 UI 디자이너");
  // Planning (2)
  insertAgent.run(randomUUID(), "Sage",  "세이지", "planning",   "team_leader", "codex",    "🧠",   "전략 분석가");
  insertAgent.run(randomUUID(), "Clio",  "클리오", "planning",   "senior",      "claude",   "📝",   "데이터 기반 기획자");
  // Operations (2)
  insertAgent.run(randomUUID(), "Atlas", "아틀라스","operations", "team_leader", "claude",   "🗺️",  "운영의 달인");
  insertAgent.run(randomUUID(), "Turbo", "터보",   "operations", "senior",      "codex",    "🚀",   "자동화 전문가");
  // QA/QC (2)
  insertAgent.run(randomUUID(), "Hawk",  "호크",   "qa",         "team_leader", "claude",   "🦅",   "날카로운 품질 감시자");
  insertAgent.run(randomUUID(), "Lint",  "린트",   "qa",         "senior",      "codex",    "🔬",   "꼼꼼한 테스트 전문가");
  // DevSecOps (2)
  insertAgent.run(randomUUID(), "Vault", "볼트S",  "devsecops",  "team_leader", "claude",   "🛡️",  "보안 아키텍트");
  insertAgent.run(randomUUID(), "Pipe",  "파이프", "devsecops",  "senior",      "codex",    "🔧",   "CI/CD 파이프라인 전문가");
  console.log("[CLImpire] Seeded default agents");
}

// Seed default settings if none exist
{
  const settingsCount = (db.prepare("SELECT COUNT(*) as c FROM settings").get() as { c: number }).c;
  if (settingsCount === 0) {
    const insertSetting = db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)");
    insertSetting.run("companyName", "CLImpire Corp.");
    insertSetting.run("ceoName", "CEO");
    insertSetting.run("autoAssign", "true");
    console.log("[CLImpire] Seeded default settings");
  }
}

// Migrate: add sort_order column & set correct ordering for existing DBs
{
  try { db.exec("ALTER TABLE departments ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 99"); } catch { /* already exists */ }

  const DEPT_ORDER: Record<string, number> = { planning: 1, dev: 2, design: 3, qa: 4, devsecops: 5, operations: 6 };
  const updateOrder = db.prepare("UPDATE departments SET sort_order = ? WHERE id = ?");
  for (const [id, order] of Object.entries(DEPT_ORDER)) {
    updateOrder.run(order, id);
  }

  const insertDeptIfMissing = db.prepare(
    "INSERT OR IGNORE INTO departments (id, name, name_ko, icon, color, sort_order) VALUES (?, ?, ?, ?, ?, ?)"
  );
  insertDeptIfMissing.run("qa", "QA/QC", "품질관리팀", "🔍", "#ef4444", 4);
  insertDeptIfMissing.run("devsecops", "DevSecOps", "인프라보안팀", "🛡️", "#f97316", 5);

  const insertAgentIfMissing = db.prepare(
    `INSERT OR IGNORE INTO agents (id, name, name_ko, department_id, role, cli_provider, avatar_emoji, personality)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  // Check which agents exist by name to avoid duplicates
  const existingNames = new Set(
    (db.prepare("SELECT name FROM agents").all() as { name: string }[]).map((r) => r.name)
  );

  const newAgents: [string, string, string, string, string, string, string][] = [
    // [name, name_ko, dept, role, provider, emoji, personality]
    ["Luna",  "루나",   "design",     "junior",      "gemini",   "🌙",  "감성적인 UI 디자이너"],
    ["Clio",  "클리오", "planning",   "senior",      "claude",   "📝",  "데이터 기반 기획자"],
    ["Turbo", "터보",   "operations", "senior",      "codex",    "🚀",  "자동화 전문가"],
    ["Hawk",  "호크",   "qa",         "team_leader", "claude",   "🦅",  "날카로운 품질 감시자"],
    ["Lint",  "린트",   "qa",         "senior",      "opencode", "🔬",  "꼼꼼한 테스트 전문가"],
    ["Vault", "볼트S",  "devsecops",  "team_leader", "claude",   "🛡️", "보안 아키텍트"],
    ["Pipe",  "파이프", "devsecops",  "senior",      "codex",    "🔧",  "CI/CD 파이프라인 전문가"],
  ];

  let added = 0;
  for (const [name, nameKo, dept, role, provider, emoji, personality] of newAgents) {
    if (!existingNames.has(name)) {
      insertAgentIfMissing.run(randomUUID(), name, nameKo, dept, role, provider, emoji, personality);
      added++;
    }
  }
  if (added > 0) console.log(`[CLImpire] Added ${added} new agents`);
}

// ---------------------------------------------------------------------------
// Track active child processes
// ---------------------------------------------------------------------------
const activeProcesses = new Map<string, ChildProcess>();

// ---------------------------------------------------------------------------
// Git Worktree support — agent isolation per task
// ---------------------------------------------------------------------------
const taskWorktrees = new Map<string, {
  worktreePath: string;
  branchName: string;
  projectPath: string; // original project path
}>();

function isGitRepo(dir: string): boolean {
  try {
    execFileSync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: dir, stdio: "pipe", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function createWorktree(projectPath: string, taskId: string, agentName: string): string | null {
  if (!isGitRepo(projectPath)) return null;

  const shortId = taskId.slice(0, 8);
  const branchName = `climpire/${shortId}`;
  const worktreeBase = path.join(projectPath, ".climpire-worktrees");
  const worktreePath = path.join(worktreeBase, shortId);

  try {
    fs.mkdirSync(worktreeBase, { recursive: true });

    // Get current branch/HEAD as base
    const base = execFileSync("git", ["rev-parse", "HEAD"], { cwd: projectPath, stdio: "pipe", timeout: 5000 }).toString().trim();

    // Create worktree with new branch
    execFileSync("git", ["worktree", "add", worktreePath, "-b", branchName, base], {
      cwd: projectPath,
      stdio: "pipe",
      timeout: 15000,
    });

    taskWorktrees.set(taskId, { worktreePath, branchName, projectPath });
    console.log(`[CLImpire] Created worktree for task ${shortId}: ${worktreePath} (branch: ${branchName}, agent: ${agentName})`);
    return worktreePath;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[CLImpire] Failed to create worktree for task ${shortId}: ${msg}`);
    return null;
  }
}

function mergeWorktree(projectPath: string, taskId: string): { success: boolean; message: string; conflicts?: string[] } {
  const info = taskWorktrees.get(taskId);
  if (!info) return { success: false, message: "No worktree found for this task" };

  try {
    // Get current branch name in the original repo
    const currentBranch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: projectPath, stdio: "pipe", timeout: 5000,
    }).toString().trim();

    // Check if there are actual changes to merge
    try {
      const diffCheck = execFileSync("git", ["diff", `${currentBranch}...${info.branchName}`, "--stat"], {
        cwd: projectPath, stdio: "pipe", timeout: 10000,
      }).toString().trim();
      if (!diffCheck) {
        return { success: true, message: "변경사항 없음 — 병합 불필요" };
      }
    } catch { /* proceed with merge attempt anyway */ }

    // Attempt merge with no-ff
    const mergeMsg = `Merge climpire task ${taskId.slice(0, 8)} (branch ${info.branchName})`;
    execFileSync("git", ["merge", info.branchName, "--no-ff", "-m", mergeMsg], {
      cwd: projectPath, stdio: "pipe", timeout: 30000,
    });

    return { success: true, message: `병합 완료: ${info.branchName} → ${currentBranch}` };
  } catch (err: unknown) {
    // Detect conflicts by checking git status instead of parsing error messages
    try {
      const unmerged = execFileSync("git", ["diff", "--name-only", "--diff-filter=U"], {
        cwd: projectPath, stdio: "pipe", timeout: 5000,
      }).toString().trim();
      const conflicts = unmerged ? unmerged.split("\n").filter(Boolean) : [];

      if (conflicts.length > 0) {
        // Abort the failed merge
        try { execFileSync("git", ["merge", "--abort"], { cwd: projectPath, stdio: "pipe", timeout: 5000 }); } catch { /* ignore */ }

        return {
          success: false,
          message: `병합 충돌 발생: ${conflicts.length}개 파일에서 충돌이 있습니다. 수동 해결이 필요합니다.`,
          conflicts,
        };
      }
    } catch { /* ignore conflict detection failure */ }

    // Abort any partial merge
    try { execFileSync("git", ["merge", "--abort"], { cwd: projectPath, stdio: "pipe", timeout: 5000 }); } catch { /* ignore */ }

    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `병합 실패: ${msg}` };
  }
}

function cleanupWorktree(projectPath: string, taskId: string): void {
  const info = taskWorktrees.get(taskId);
  if (!info) return;

  const shortId = taskId.slice(0, 8);

  try {
    // Remove worktree
    execFileSync("git", ["worktree", "remove", info.worktreePath, "--force"], {
      cwd: projectPath, stdio: "pipe", timeout: 10000,
    });
  } catch {
    // If worktree remove fails, try manual cleanup
    console.warn(`[CLImpire] git worktree remove failed for ${shortId}, falling back to manual cleanup`);
    try {
      if (fs.existsSync(info.worktreePath)) {
        fs.rmSync(info.worktreePath, { recursive: true, force: true });
      }
      execFileSync("git", ["worktree", "prune"], { cwd: projectPath, stdio: "pipe", timeout: 5000 });
    } catch { /* ignore */ }
  }

  try {
    // Delete branch
    execFileSync("git", ["branch", "-D", info.branchName], {
      cwd: projectPath, stdio: "pipe", timeout: 5000,
    });
  } catch {
    console.warn(`[CLImpire] Failed to delete branch ${info.branchName} — may need manual cleanup`);
  }

  taskWorktrees.delete(taskId);
  console.log(`[CLImpire] Cleaned up worktree for task ${shortId}`);
}

function getWorktreeDiffSummary(projectPath: string, taskId: string): string {
  const info = taskWorktrees.get(taskId);
  if (!info) return "";

  try {
    // Get current branch in original repo
    const currentBranch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: projectPath, stdio: "pipe", timeout: 5000,
    }).toString().trim();

    const stat = execFileSync("git", ["diff", `${currentBranch}...${info.branchName}`, "--stat"], {
      cwd: projectPath, stdio: "pipe", timeout: 10000,
    }).toString().trim();

    return stat || "변경사항 없음";
  } catch {
    return "diff 조회 실패";
  }
}

// ---------------------------------------------------------------------------
// WebSocket setup
// ---------------------------------------------------------------------------
const wsClients = new Set<WebSocket>();

function broadcast(type: string, payload: unknown): void {
  const message = JSON.stringify({ type, payload, ts: nowMs() });
  for (const ws of wsClients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  }
}

// ---------------------------------------------------------------------------
// CLI spawn helpers (ported from claw-kanban)
// ---------------------------------------------------------------------------
function buildAgentArgs(provider: string): string[] {
  switch (provider) {
    case "codex":
      return ["codex", "--yolo", "exec", "--json"];
    case "claude":
      return [
        "claude",
        "--dangerously-skip-permissions",
        "--print",
        "--verbose",
        "--output-format=stream-json",
        "--include-partial-messages",
      ];
    case "gemini":
      return ["gemini", "--yolo", "--output-format=stream-json"];
    case "opencode":
      return ["opencode", "run", "--format", "json"];
    case "copilot":
    case "antigravity":
      throw new Error(`${provider} uses HTTP agent (not CLI spawn)`);
    default:
      throw new Error(`unsupported CLI provider: ${provider}`);
  }
}

/** Fetch recent conversation context for an agent to include in spawn prompt */
function getRecentConversationContext(agentId: string, limit = 10): string {
  const msgs = db.prepare(`
    SELECT sender_type, sender_id, content, message_type, created_at
    FROM messages
    WHERE (
      (sender_type = 'ceo' AND receiver_type = 'agent' AND receiver_id = ?)
      OR (sender_type = 'agent' AND sender_id = ?)
      OR (receiver_type = 'all')
    )
    ORDER BY created_at DESC
    LIMIT ?
  `).all(agentId, agentId, limit) as Array<{
    sender_type: string;
    sender_id: string | null;
    content: string;
    message_type: string;
    created_at: number;
  }>;

  if (msgs.length === 0) return "";

  const lines = msgs.reverse().map((m) => {
    const role = m.sender_type === "ceo" ? "CEO" : "Agent";
    const type = m.message_type !== "chat" ? ` [${m.message_type}]` : "";
    return `${role}${type}: ${m.content}`;
  });

  return `\n\n--- Recent conversation context ---\n${lines.join("\n")}\n--- End context ---`;
}

function spawnCliAgent(
  taskId: string,
  provider: string,
  prompt: string,
  projectPath: string,
  logPath: string,
): ChildProcess {
  // Save prompt for debugging
  const promptPath = path.join(logsDir, `${taskId}.prompt.txt`);
  fs.writeFileSync(promptPath, prompt, "utf8");

  const args = buildAgentArgs(provider);
  const logStream = fs.createWriteStream(logPath, { flags: "w" });

  // Remove CLAUDECODE env var to prevent "nested session" detection
  const cleanEnv = { ...process.env };
  delete cleanEnv.CLAUDECODE;
  delete cleanEnv.CLAUDE_CODE;

  const child = spawn(args[0], args.slice(1), {
    cwd: projectPath,
    env: cleanEnv,
    shell: process.platform === "win32",
    stdio: ["pipe", "pipe", "pipe"],
    detached: process.platform !== "win32",
    windowsHide: true,
  });

  activeProcesses.set(taskId, child);

  child.on("error", (err) => {
    console.error(`[CLImpire] spawn error for ${provider} (task ${taskId}): ${err.message}`);
    logStream.write(`\n[CLImpire] SPAWN ERROR: ${err.message}\n`);
    logStream.end();
    activeProcesses.delete(taskId);
    appendTaskLog(taskId, "error", `Agent spawn failed: ${err.message}`);
  });

  // Deliver prompt via stdin (cross-platform safe)
  child.stdin?.write(prompt);
  child.stdin?.end();

  // Pipe agent output to log file AND broadcast via WebSocket
  child.stdout?.on("data", (chunk: Buffer) => {
    logStream.write(chunk);
    broadcast("cli_output", { task_id: taskId, stream: "stdout", data: chunk.toString("utf8") });
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    logStream.write(chunk);
    broadcast("cli_output", { task_id: taskId, stream: "stderr", data: chunk.toString("utf8") });
  });

  child.on("close", () => {
    logStream.end();
    try { fs.unlinkSync(promptPath); } catch { /* ignore */ }
  });

  if (process.platform !== "win32") child.unref();

  return child;
}

function killPidTree(pid: number): void {
  if (process.platform === "win32") {
    try {
      execFile("taskkill", ["/pid", String(pid), "/T", "/F"], { timeout: 5000 }, () => {});
    } catch { /* ignore */ }
  } else {
    try { process.kill(-pid, "SIGTERM"); } catch { /* ignore */ }
    try { process.kill(pid, "SIGTERM"); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Task log helpers
// ---------------------------------------------------------------------------
function appendTaskLog(taskId: string, kind: string, message: string): void {
  const t = nowMs();
  db.prepare(
    "INSERT INTO task_logs (task_id, kind, message, created_at) VALUES (?, ?, ?, ?)"
  ).run(taskId, kind, message, t);
}

// ---------------------------------------------------------------------------
// CLI Detection (ported from claw-kanban)
// ---------------------------------------------------------------------------
interface CliToolStatus {
  installed: boolean;
  version: string | null;
  authenticated: boolean;
  authHint: string;
}

type CliStatusResult = Record<string, CliToolStatus>;

let cachedCliStatus: { data: CliStatusResult; loadedAt: number } | null = null;
const CLI_STATUS_TTL = 30_000;

interface CliToolDef {
  name: string;
  authHint: string;
  checkAuth: () => boolean;
}

function jsonHasKey(filePath: string, key: string): boolean {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const j = JSON.parse(raw);
    return j != null && typeof j === "object" && key in j && j[key] != null;
  } catch {
    return false;
  }
}

function fileExistsNonEmpty(filePath: string): boolean {
  try {
    const stat = fs.statSync(filePath);
    return stat.isFile() && stat.size > 2;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// CLI Usage Types
// ---------------------------------------------------------------------------
interface CliUsageWindow {
  label: string;
  utilization: number;
  resetsAt: string | null;
}

interface CliUsageEntry {
  windows: CliUsageWindow[];
  error: string | null;
}

// ---------------------------------------------------------------------------
// Credential Readers
// ---------------------------------------------------------------------------
function readClaudeToken(): string | null {
  // macOS Keychain first (primary on macOS)
  if (process.platform === "darwin") {
    try {
      const raw = execFileSync("security", [
        "find-generic-password", "-s", "Claude Code-credentials", "-w",
      ], { timeout: 3000 }).toString().trim();
      const j = JSON.parse(raw);
      if (j?.claudeAiOauth?.accessToken) return j.claudeAiOauth.accessToken;
    } catch { /* ignore */ }
  }
  // Fallback: file on disk
  const home = os.homedir();
  try {
    const credsPath = path.join(home, ".claude", ".credentials.json");
    if (fs.existsSync(credsPath)) {
      const j = JSON.parse(fs.readFileSync(credsPath, "utf8"));
      if (j?.claudeAiOauth?.accessToken) return j.claudeAiOauth.accessToken;
    }
  } catch { /* ignore */ }
  return null;
}

function readCodexTokens(): { access_token: string; account_id: string } | null {
  try {
    const authPath = path.join(os.homedir(), ".codex", "auth.json");
    const j = JSON.parse(fs.readFileSync(authPath, "utf8"));
    if (j?.tokens?.access_token && j?.tokens?.account_id) {
      return { access_token: j.tokens.access_token, account_id: j.tokens.account_id };
    }
  } catch { /* ignore */ }
  return null;
}

// Gemini OAuth client credentials (public installed-app creds from Gemini CLI source;
// safe to embed per Google's installed app guidelines)
const GEMINI_OAUTH_CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
const GEMINI_OAUTH_CLIENT_SECRET = "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";

interface GeminiCreds {
  access_token: string;
  refresh_token: string;
  expiry_date: number;
  source: "keychain" | "file";
}

function readGeminiCredsFromKeychain(): GeminiCreds | null {
  if (process.platform !== "darwin") return null;
  try {
    const raw = execFileSync("security", [
      "find-generic-password", "-s", "gemini-cli-oauth", "-a", "main-account", "-w",
    ], { timeout: 3000, stdio: ["pipe", "pipe", "pipe"] }).toString().trim();
    if (!raw) return null;
    const stored = JSON.parse(raw);
    if (!stored?.token?.accessToken) return null;
    return {
      access_token: stored.token.accessToken,
      refresh_token: stored.token.refreshToken ?? "",
      expiry_date: stored.token.expiresAt ?? 0,
      source: "keychain",
    };
  } catch { return null; }
}

function readGeminiCredsFromFile(): GeminiCreds | null {
  try {
    const p = path.join(os.homedir(), ".gemini", "oauth_creds.json");
    const j = JSON.parse(fs.readFileSync(p, "utf8"));
    if (j?.access_token) {
      return {
        access_token: j.access_token,
        refresh_token: j.refresh_token ?? "",
        expiry_date: j.expiry_date ?? 0,
        source: "file",
      };
    }
  } catch { /* ignore */ }
  return null;
}

function readGeminiCreds(): GeminiCreds | null {
  // macOS Keychain first, then file fallback
  return readGeminiCredsFromKeychain() ?? readGeminiCredsFromFile();
}

async function freshGeminiToken(): Promise<string | null> {
  const creds = readGeminiCreds();
  if (!creds) return null;
  // If not expired (5-minute buffer), reuse
  if (creds.expiry_date > Date.now() + 300_000) return creds.access_token;
  // Cannot refresh without refresh_token
  if (!creds.refresh_token) return creds.access_token; // try existing token anyway
  // Refresh using Gemini CLI's public OAuth client credentials
  try {
    const resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GEMINI_OAUTH_CLIENT_ID,
        client_secret: GEMINI_OAUTH_CLIENT_SECRET,
        refresh_token: creds.refresh_token,
        grant_type: "refresh_token",
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return creds.access_token; // fall back to existing token
    const data = await resp.json() as { access_token?: string; expires_in?: number; refresh_token?: string };
    if (!data.access_token) return creds.access_token;
    // Persist refreshed token back to file (only if source was file)
    if (creds.source === "file") {
      try {
        const p = path.join(os.homedir(), ".gemini", "oauth_creds.json");
        const raw = JSON.parse(fs.readFileSync(p, "utf8"));
        raw.access_token = data.access_token;
        if (data.refresh_token) raw.refresh_token = data.refresh_token;
        raw.expiry_date = Date.now() + (data.expires_in ?? 3600) * 1000;
        fs.writeFileSync(p, JSON.stringify(raw, null, 2), { mode: 0o600 });
      } catch { /* ignore write failure */ }
    }
    return data.access_token;
  } catch { return creds.access_token; } // fall back to existing token on network error
}

// ---------------------------------------------------------------------------
// Provider Fetch Functions
// ---------------------------------------------------------------------------

// Claude: utilization is already 0-100 (percentage), NOT a fraction
async function fetchClaudeUsage(): Promise<CliUsageEntry> {
  const token = readClaudeToken();
  if (!token) return { windows: [], error: "unauthenticated" };
  try {
    const resp = await fetch("https://api.anthropic.com/api/oauth/usage", {
      headers: {
        "Authorization": `Bearer ${token}`,
        "anthropic-beta": "oauth-2025-04-20",
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return { windows: [], error: `http_${resp.status}` };
    const data = await resp.json() as Record<string, { utilization?: number; resets_at?: string } | null>;
    const windows: CliUsageWindow[] = [];
    const labelMap: Record<string, string> = {
      five_hour: "5-hour",
      seven_day: "7-day",
      seven_day_sonnet: "7-day Sonnet",
      seven_day_opus: "7-day Opus",
    };
    for (const [key, label] of Object.entries(labelMap)) {
      const entry = data[key];
      if (entry) {
        windows.push({
          label,
          utilization: Math.round(entry.utilization ?? 0) / 100, // API returns 0-100, normalize to 0-1
          resetsAt: entry.resets_at ?? null,
        });
      }
    }
    return { windows, error: null };
  } catch {
    return { windows: [], error: "unavailable" };
  }
}

// Codex: uses primary_window/secondary_window with used_percent (0-100), reset_at is Unix seconds
async function fetchCodexUsage(): Promise<CliUsageEntry> {
  const tokens = readCodexTokens();
  if (!tokens) return { windows: [], error: "unauthenticated" };
  try {
    const resp = await fetch("https://chatgpt.com/backend-api/wham/usage", {
      headers: {
        "Authorization": `Bearer ${tokens.access_token}`,
        "ChatGPT-Account-Id": tokens.account_id,
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return { windows: [], error: `http_${resp.status}` };
    const data = await resp.json() as {
      rate_limit?: {
        primary_window?: { used_percent?: number; reset_at?: number };
        secondary_window?: { used_percent?: number; reset_at?: number };
      };
    };
    const windows: CliUsageWindow[] = [];
    if (data.rate_limit?.primary_window) {
      const pw = data.rate_limit.primary_window;
      windows.push({
        label: "5-hour",
        utilization: (pw.used_percent ?? 0) / 100,
        resetsAt: pw.reset_at ? new Date(pw.reset_at * 1000).toISOString() : null,
      });
    }
    if (data.rate_limit?.secondary_window) {
      const sw = data.rate_limit.secondary_window;
      windows.push({
        label: "7-day",
        utilization: (sw.used_percent ?? 0) / 100,
        resetsAt: sw.reset_at ? new Date(sw.reset_at * 1000).toISOString() : null,
      });
    }
    return { windows, error: null };
  } catch {
    return { windows: [], error: "unavailable" };
  }
}

// Gemini: requires project ID from loadCodeAssist, then POST retrieveUserQuota
let geminiProjectCache: { id: string; fetchedAt: number } | null = null;
const GEMINI_PROJECT_TTL = 300_000; // 5 minutes

async function getGeminiProjectId(token: string): Promise<string | null> {
  // 1. Environment variable (CI / custom setups)
  const envProject = process.env.GOOGLE_CLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT_ID;
  if (envProject) return envProject;

  // 2. Gemini CLI settings file
  try {
    const settingsPath = path.join(os.homedir(), ".gemini", "settings.json");
    const j = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    if (j?.cloudaicompanionProject) return j.cloudaicompanionProject;
  } catch { /* ignore */ }

  // 3. In-memory cache with TTL
  if (geminiProjectCache && Date.now() - geminiProjectCache.fetchedAt < GEMINI_PROJECT_TTL) {
    return geminiProjectCache.id;
  }

  // 4. Fetch via loadCodeAssist API (discovers project for the authenticated user)
  try {
    const resp = await fetch("https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        metadata: { ideType: "GEMINI_CLI", platform: "PLATFORM_UNSPECIFIED", pluginType: "GEMINI" },
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return null;
    const data = await resp.json() as { cloudaicompanionProject?: string };
    if (data.cloudaicompanionProject) {
      geminiProjectCache = { id: data.cloudaicompanionProject, fetchedAt: Date.now() };
      return geminiProjectCache.id;
    }
  } catch { /* ignore */ }
  return null;
}

async function fetchGeminiUsage(): Promise<CliUsageEntry> {
  const token = await freshGeminiToken();
  if (!token) return { windows: [], error: "unauthenticated" };

  const projectId = await getGeminiProjectId(token);
  if (!projectId) return { windows: [], error: "unavailable" };

  try {
    const resp = await fetch("https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ project: projectId }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return { windows: [], error: `http_${resp.status}` };
    const data = await resp.json() as {
      buckets?: Array<{ modelId?: string; remainingFraction?: number; resetTime?: string }>;
    };
    const windows: CliUsageWindow[] = [];
    if (data.buckets) {
      for (const b of data.buckets) {
        // Skip _vertex duplicates
        if (b.modelId?.endsWith("_vertex")) continue;
        windows.push({
          label: b.modelId ?? "Quota",
          utilization: Math.round((1 - (b.remainingFraction ?? 1)) * 100) / 100,
          resetsAt: b.resetTime ?? null,
        });
      }
    }
    return { windows, error: null };
  } catch {
    return { windows: [], error: "unavailable" };
  }
}

// ---------------------------------------------------------------------------
// CLI Tool Definitions
// ---------------------------------------------------------------------------

const CLI_TOOLS: CliToolDef[] = [
  {
    name: "claude",
    authHint: "Run: claude login",
    checkAuth: () => {
      const home = os.homedir();
      if (jsonHasKey(path.join(home, ".claude.json"), "oauthAccount")) return true;
      return fileExistsNonEmpty(path.join(home, ".claude", "auth.json"));
    },
  },
  {
    name: "codex",
    authHint: "Run: codex auth login",
    checkAuth: () => {
      const authPath = path.join(os.homedir(), ".codex", "auth.json");
      if (jsonHasKey(authPath, "OPENAI_API_KEY") || jsonHasKey(authPath, "tokens")) return true;
      if (process.env.OPENAI_API_KEY) return true;
      return false;
    },
  },
  {
    name: "gemini",
    authHint: "Run: gemini auth login",
    checkAuth: () => {
      // macOS Keychain
      if (readGeminiCredsFromKeychain()) return true;
      // File-based credentials
      if (jsonHasKey(path.join(os.homedir(), ".gemini", "oauth_creds.json"), "access_token")) return true;
      // Windows gcloud ADC fallback
      const appData = process.env.APPDATA;
      if (appData && jsonHasKey(path.join(appData, "gcloud", "application_default_credentials.json"), "client_id")) return true;
      return false;
    },
  },
  {
    name: "opencode",
    authHint: "Run: opencode auth",
    checkAuth: () => {
      const home = os.homedir();
      if (fileExistsNonEmpty(path.join(home, ".local", "share", "opencode", "auth.json"))) return true;
      const xdgData = process.env.XDG_DATA_HOME;
      if (xdgData && fileExistsNonEmpty(path.join(xdgData, "opencode", "auth.json"))) return true;
      if (process.platform === "darwin") {
        if (fileExistsNonEmpty(path.join(home, "Library", "Application Support", "opencode", "auth.json"))) return true;
      }
      return false;
    },
  },
];

function execWithTimeout(cmd: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile(cmd, args, { timeout: timeoutMs }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout.trim());
    });
    child.unref?.();
  });
}

async function detectCliTool(tool: CliToolDef): Promise<CliToolStatus> {
  const whichCmd = process.platform === "win32" ? "where" : "which";
  try {
    await execWithTimeout(whichCmd, [tool.name], 3000);
  } catch {
    return { installed: false, version: null, authenticated: false, authHint: tool.authHint };
  }

  let version: string | null = null;
  try {
    version = await execWithTimeout(tool.name, ["--version"], 3000);
    if (version.includes("\n")) version = version.split("\n")[0].trim();
  } catch { /* binary found but --version failed */ }

  const authenticated = tool.checkAuth();
  return { installed: true, version, authenticated, authHint: tool.authHint };
}

async function detectAllCli(): Promise<CliStatusResult> {
  const results = await Promise.all(CLI_TOOLS.map((t) => detectCliTool(t)));
  const out: CliStatusResult = {};
  for (let i = 0; i < CLI_TOOLS.length; i++) {
    out[CLI_TOOLS[i].name] = results[i];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Helpers: progress timers, CEO notifications
// ---------------------------------------------------------------------------

// Track progress report timers so we can cancel them when tasks finish
const progressTimers = new Map<string, ReturnType<typeof setInterval>>();

// Cross-department sequential queue: when a cross-dept task finishes,
// trigger the next department in line (instead of spawning all simultaneously).
// Key: cross-dept task ID → callback to start next department
const crossDeptNextCallbacks = new Map<string, () => void>();

function startProgressTimer(taskId: string, taskTitle: string, departmentId: string | null): void {
  // Send progress report every 5min for long-running tasks
  const timer = setInterval(() => {
    const currentTask = db.prepare("SELECT status FROM tasks WHERE id = ?").get(taskId) as { status: string } | undefined;
    if (!currentTask || currentTask.status !== "in_progress") {
      clearInterval(timer);
      progressTimers.delete(taskId);
      return;
    }
    const leader = findTeamLeader(departmentId);
    if (leader) {
      sendAgentMessage(
        leader,
        `대표님, '${taskTitle}' 작업 진행 중입니다. 현재 순조롭게 진행되고 있어요.`,
        "report",
        "all",
        null,
        taskId,
      );
    }
  }, 300_000);
  progressTimers.set(taskId, timer);
}

function stopProgressTimer(taskId: string): void {
  const timer = progressTimers.get(taskId);
  if (timer) {
    clearInterval(timer);
    progressTimers.delete(taskId);
  }
}

// ---------------------------------------------------------------------------
// Send CEO notification for all significant workflow events (B4)
// ---------------------------------------------------------------------------
function notifyCeo(content: string, taskId: string | null = null, messageType: string = "status_update"): void {
  const msgId = randomUUID();
  const t = nowMs();
  db.prepare(
    `INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
     VALUES (?, 'system', NULL, 'all', NULL, ?, ?, ?, ?)`
  ).run(msgId, content, messageType, taskId, t);
  broadcast("new_message", {
    id: msgId,
    sender_type: "system",
    content,
    message_type: messageType,
    task_id: taskId,
    created_at: t,
  });
}

// ---------------------------------------------------------------------------
// Run completion handler — enhanced with review flow + CEO reporting
// ---------------------------------------------------------------------------
function handleTaskRunComplete(taskId: string, exitCode: number): void {
  activeProcesses.delete(taskId);
  stopProgressTimer(taskId);

  const t = nowMs();
  const logKind = exitCode === 0 ? "completed" : "failed";

  appendTaskLog(taskId, "system", `RUN ${logKind} (exit code: ${exitCode})`);

  // Get task info
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
    assigned_agent_id: string | null;
    department_id: string | null;
    title: string;
  } | undefined;

  // Read log file for result
  const logPath = path.join(logsDir, `${taskId}.log`);
  let result: string | null = null;
  try {
    if (fs.existsSync(logPath)) {
      const raw = fs.readFileSync(logPath, "utf8");
      result = raw.slice(-2000);
    }
  } catch { /* ignore */ }

  if (result) {
    db.prepare("UPDATE tasks SET result = ? WHERE id = ?").run(result, taskId);
  }

  // Update agent status back to idle
  if (task?.assigned_agent_id) {
    db.prepare(
      "UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?"
    ).run(task.assigned_agent_id);

    if (exitCode === 0) {
      db.prepare(
        "UPDATE agents SET stats_tasks_done = stats_tasks_done + 1, stats_xp = stats_xp + 10 WHERE id = ?"
      ).run(task.assigned_agent_id);
    }

    const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(task.assigned_agent_id) as Record<string, unknown> | undefined;
    broadcast("agent_status", agent);
  }

  if (exitCode === 0) {
    // ── SUCCESS: Move to 'review' for team leader check ──
    db.prepare(
      "UPDATE tasks SET status = 'review', updated_at = ? WHERE id = ?"
    ).run(t, taskId);

    appendTaskLog(taskId, "system", "Status → review (team leader review pending)");

    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
    broadcast("task_update", updatedTask);

    // Notify: task entering review
    if (task) {
      const leader = findTeamLeader(task.department_id);
      const leaderName = leader?.name_ko || leader?.name || "팀장";
      notifyCeo(`${leaderName}이(가) '${task.title}' 결과를 검토 중입니다.`, taskId);
    }

    // Schedule team leader review message (2-3s delay)
    setTimeout(() => {
      if (!task) return;
      const leader = findTeamLeader(task.department_id);
      if (!leader) {
        // No team leader — auto-approve
        finishReview(taskId, task.title);
        return;
      }

      // Read the task result and pretty-parse it for the report
      let reportBody = "";
      try {
        const logFile = path.join(logsDir, `${taskId}.log`);
        if (fs.existsSync(logFile)) {
          const raw = fs.readFileSync(logFile, "utf8");
          const pretty = prettyStreamJson(raw);
          // Take the last ~500 chars of the pretty output as summary
          reportBody = pretty.length > 500 ? "..." + pretty.slice(-500) : pretty;
        }
      } catch { /* ignore */ }

      // If worktree exists, include diff summary in the report
      const wtInfo = taskWorktrees.get(taskId);
      let diffSummary = "";
      if (wtInfo) {
        diffSummary = getWorktreeDiffSummary(wtInfo.projectPath, taskId);
        if (diffSummary && diffSummary !== "변경사항 없음") {
          appendTaskLog(taskId, "system", `Worktree diff summary:\n${diffSummary}`);
        }
      }

      // Team leader sends completion report with actual result content + diff
      let reportContent = reportBody
        ? `대표님, '${task.title}' 업무 완료 보고드립니다.\n\n📋 결과:\n${reportBody}`
        : `대표님, '${task.title}' 업무 완료 보고드립니다. 작업이 성공적으로 마무리되었습니다.`;

      if (diffSummary && diffSummary !== "변경사항 없음" && diffSummary !== "diff 조회 실패") {
        reportContent += `\n\n📝 변경사항 (branch: ${wtInfo?.branchName}):\n${diffSummary}`;
      }

      sendAgentMessage(
        leader,
        reportContent,
        "report",
        "all",
        null,
        taskId,
      );

      // After another 2-3s: team leader approves → move to done
      setTimeout(() => {
        finishReview(taskId, task.title);
      }, 2500);
    }, 2500);

  } else {
    // ── FAILURE: Reset to inbox, team leader reports failure ──
    db.prepare(
      "UPDATE tasks SET status = 'inbox', updated_at = ? WHERE id = ?"
    ).run(t, taskId);

    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
    broadcast("task_update", updatedTask);

    // Clean up worktree on failure — failed work shouldn't persist
    const failWtInfo = taskWorktrees.get(taskId);
    if (failWtInfo) {
      cleanupWorktree(failWtInfo.projectPath, taskId);
      appendTaskLog(taskId, "system", "Worktree cleaned up (task failed)");
    }

    if (task) {
      const leader = findTeamLeader(task.department_id);
      if (leader) {
        setTimeout(() => {
          // Read error output for failure report
          let errorBody = "";
          try {
            const logFile = path.join(logsDir, `${taskId}.log`);
            if (fs.existsSync(logFile)) {
              const raw = fs.readFileSync(logFile, "utf8");
              const pretty = prettyStreamJson(raw);
              errorBody = pretty.length > 300 ? "..." + pretty.slice(-300) : pretty;
            }
          } catch { /* ignore */ }

          const failContent = errorBody
            ? `대표님, '${task.title}' 작업에 문제가 발생했습니다 (종료코드: ${exitCode}).\n\n❌ 오류 내용:\n${errorBody}\n\n재배정하거나 업무 내용을 수정한 후 다시 시도해주세요.`
            : `대표님, '${task.title}' 작업에 문제가 발생했습니다 (종료코드: ${exitCode}). 에이전트를 재배정하거나 업무 내용을 수정한 후 다시 시도해주세요.`;

          sendAgentMessage(
            leader,
            failContent,
            "report",
            "all",
            null,
            taskId,
          );
        }, 1500);
      }
      notifyCeo(`'${task.title}' 작업 실패 (exit code: ${exitCode}).`, taskId);
    }

    // Even on failure, trigger next cross-dept cooperation so the queue doesn't stall
    const nextCallback = crossDeptNextCallbacks.get(taskId);
    if (nextCallback) {
      crossDeptNextCallbacks.delete(taskId);
      setTimeout(nextCallback, 3000);
    }
  }
}

// Move a reviewed task to 'done'
function finishReview(taskId: string, taskTitle: string): void {
  const t = nowMs();
  const currentTask = db.prepare("SELECT status, department_id FROM tasks WHERE id = ?").get(taskId) as { status: string; department_id: string | null } | undefined;
  if (!currentTask || currentTask.status !== "review") return; // Already moved or cancelled

  // If task has a worktree, merge the branch back before marking done
  const wtInfo = taskWorktrees.get(taskId);
  let mergeNote = "";
  if (wtInfo) {
    const mergeResult = mergeWorktree(wtInfo.projectPath, taskId);

    if (mergeResult.success) {
      appendTaskLog(taskId, "system", `Git merge 완료: ${mergeResult.message}`);
      cleanupWorktree(wtInfo.projectPath, taskId);
      appendTaskLog(taskId, "system", "Worktree cleaned up after successful merge");
      mergeNote = " (병합 완료)";
    } else {
      // Merge conflict or failure — report to CEO, keep worktree for manual resolution
      appendTaskLog(taskId, "system", `Git merge 실패: ${mergeResult.message}`);

      const conflictLeader = findTeamLeader(currentTask.department_id);
      const conflictLeaderName = conflictLeader?.name_ko || conflictLeader?.name || "팀장";
      const conflictFiles = mergeResult.conflicts?.length
        ? `\n충돌 파일: ${mergeResult.conflicts.join(", ")}`
        : "";
      notifyCeo(
        `${conflictLeaderName}: '${taskTitle}' 병합 중 충돌이 발생했습니다. 수동 해결이 필요합니다.${conflictFiles}\n` +
        `브랜치: ${wtInfo.branchName}`,
        taskId,
      );

      mergeNote = " (병합 충돌 - 수동 해결 필요)";
      // Don't clean up worktree — keep it for manual conflict resolution
      // Still move task to done since the work itself is approved
    }
  }

  db.prepare(
    "UPDATE tasks SET status = 'done', completed_at = ?, updated_at = ? WHERE id = ?"
  ).run(t, t, taskId);

  appendTaskLog(taskId, "system", "Status → done (team leader approved)");

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
  broadcast("task_update", updatedTask);

  // Refresh CLI usage data in background after task completion
  refreshCliUsageData().then((usage) => broadcast("cli_usage_update", usage)).catch(() => {});

  const leader = findTeamLeader(currentTask.department_id);
  const leaderName = leader?.name_ko || leader?.name || "팀장";
  notifyCeo(`${leaderName}: '${taskTitle}' 완료 보고드립니다.${mergeNote}`, taskId);

  // Trigger next cross-dept cooperation if queued (sequential chain)
  const nextCallback = crossDeptNextCallbacks.get(taskId);
  if (nextCallback) {
    crossDeptNextCallbacks.delete(taskId);
    nextCallback();
  }
}

// ===========================================================================
// API ENDPOINTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
const buildHealthPayload = () => ({
  ok: true,
  version: PKG_VERSION,
  app: "CLImpire",
  dbPath,
});

app.get("/health", (_req, res) => res.json(buildHealthPayload()));
app.get("/healthz", (_req, res) => res.json(buildHealthPayload()));
app.get("/api/health", (_req, res) => res.json(buildHealthPayload()));

// ---------------------------------------------------------------------------
// Departments
// ---------------------------------------------------------------------------
app.get("/api/departments", (_req, res) => {
  const departments = db.prepare(`
    SELECT d.*,
      (SELECT COUNT(*) FROM agents a WHERE a.department_id = d.id) AS agent_count
    FROM departments d
    ORDER BY d.sort_order ASC
  `).all();
  res.json({ departments });
});

app.get("/api/departments/:id", (req, res) => {
  const id = String(req.params.id);
  const department = db.prepare("SELECT * FROM departments WHERE id = ?").get(id);
  if (!department) return res.status(404).json({ error: "not_found" });

  const agents = db.prepare("SELECT * FROM agents WHERE department_id = ? ORDER BY role, name").all(id);
  res.json({ department, agents });
});

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------
app.get("/api/agents", (_req, res) => {
  const agents = db.prepare(`
    SELECT a.*, d.name AS department_name, d.name_ko AS department_name_ko, d.color AS department_color
    FROM agents a
    LEFT JOIN departments d ON a.department_id = d.id
    ORDER BY a.department_id, a.role, a.name
  `).all();
  res.json({ agents });
});

app.get("/api/agents/:id", (req, res) => {
  const id = String(req.params.id);
  const agent = db.prepare(`
    SELECT a.*, d.name AS department_name, d.name_ko AS department_name_ko, d.color AS department_color
    FROM agents a
    LEFT JOIN departments d ON a.department_id = d.id
    WHERE a.id = ?
  `).get(id);
  if (!agent) return res.status(404).json({ error: "not_found" });

  // Include recent tasks
  const recentTasks = db.prepare(
    "SELECT * FROM tasks WHERE assigned_agent_id = ? ORDER BY updated_at DESC LIMIT 10"
  ).all(id);

  res.json({ agent, recent_tasks: recentTasks });
});

app.patch("/api/agents/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  if (!existing) return res.status(404).json({ error: "not_found" });

  const body = req.body ?? {};
  const allowedFields = [
    "name", "name_ko", "department_id", "role", "cli_provider",
    "avatar_emoji", "personality", "status", "current_task_id",
  ];

  const updates: string[] = [];
  const params: unknown[] = [];

  for (const field of allowedFields) {
    if (field in body) {
      updates.push(`${field} = ?`);
      params.push(body[field]);
    }
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: "no_fields_to_update" });
  }

  params.push(id);
  db.prepare(`UPDATE agents SET ${updates.join(", ")} WHERE id = ?`).run(...params);

  const updated = db.prepare("SELECT * FROM agents WHERE id = ?").get(id);
  broadcast("agent_status", updated);
  res.json({ ok: true, agent: updated });
});

app.post("/api/agents/:id/spawn", (req, res) => {
  const id = String(req.params.id);
  const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as {
    id: string;
    name: string;
    cli_provider: string | null;
    current_task_id: string | null;
    status: string;
  } | undefined;
  if (!agent) return res.status(404).json({ error: "not_found" });

  const provider = agent.cli_provider || "claude";
  if (!["claude", "codex", "gemini", "opencode"].includes(provider)) {
    return res.status(400).json({ error: "unsupported_provider", provider });
  }

  const taskId = agent.current_task_id;
  if (!taskId) {
    return res.status(400).json({ error: "no_task_assigned", message: "Assign a task to this agent first." });
  }

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
    id: string;
    title: string;
    description: string | null;
    project_path: string | null;
  } | undefined;
  if (!task) {
    return res.status(400).json({ error: "task_not_found" });
  }

  const projectPath = task.project_path || process.cwd();
  const logPath = path.join(logsDir, `${taskId}.log`);

  const prompt = `${task.title}\n\n${task.description || ""}`;

  appendTaskLog(taskId, "system", `RUN start (agent=${agent.name}, provider=${provider})`);

  const child = spawnCliAgent(taskId, provider, prompt, projectPath, logPath);

  child.on("close", (code) => {
    handleTaskRunComplete(taskId, code ?? 1);
  });

  // Update agent status
  db.prepare("UPDATE agents SET status = 'working' WHERE id = ?").run(id);
  db.prepare("UPDATE tasks SET status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?")
    .run(nowMs(), nowMs(), taskId);

  const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(id);
  broadcast("agent_status", updatedAgent);
  broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));

  res.json({ ok: true, pid: child.pid ?? null, logPath, cwd: projectPath });
});

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------
app.get("/api/tasks", (req, res) => {
  const statusFilter = firstQueryValue(req.query.status);
  const deptFilter = firstQueryValue(req.query.department_id);
  const agentFilter = firstQueryValue(req.query.agent_id);

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (statusFilter) {
    conditions.push("t.status = ?");
    params.push(statusFilter);
  }
  if (deptFilter) {
    conditions.push("t.department_id = ?");
    params.push(deptFilter);
  }
  if (agentFilter) {
    conditions.push("t.assigned_agent_id = ?");
    params.push(agentFilter);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const tasks = db.prepare(`
    SELECT t.*,
      a.name AS agent_name,
      a.avatar_emoji AS agent_avatar,
      d.name AS department_name,
      d.icon AS department_icon
    FROM tasks t
    LEFT JOIN agents a ON t.assigned_agent_id = a.id
    LEFT JOIN departments d ON t.department_id = d.id
    ${where}
    ORDER BY t.priority DESC, t.updated_at DESC
  `).all(...params);

  res.json({ tasks });
});

app.post("/api/tasks", (req, res) => {
  const body = req.body ?? {};
  const id = randomUUID();
  const t = nowMs();

  const title = body.title;
  if (!title || typeof title !== "string") {
    return res.status(400).json({ error: "title_required" });
  }

  db.prepare(`
    INSERT INTO tasks (id, title, description, department_id, assigned_agent_id, status, priority, task_type, project_path, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    title,
    body.description ?? null,
    body.department_id ?? null,
    body.assigned_agent_id ?? null,
    body.status ?? "inbox",
    body.priority ?? 0,
    body.task_type ?? "general",
    body.project_path ?? null,
    t,
    t,
  );

  appendTaskLog(id, "system", `Task created: ${title}`);

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", task);
  res.json({ id, task });
});

app.get("/api/tasks/:id", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare(`
    SELECT t.*,
      a.name AS agent_name,
      a.avatar_emoji AS agent_avatar,
      a.cli_provider AS agent_provider,
      d.name AS department_name,
      d.icon AS department_icon
    FROM tasks t
    LEFT JOIN agents a ON t.assigned_agent_id = a.id
    LEFT JOIN departments d ON t.department_id = d.id
    WHERE t.id = ?
  `).get(id);
  if (!task) return res.status(404).json({ error: "not_found" });

  const logs = db.prepare(
    "SELECT * FROM task_logs WHERE task_id = ? ORDER BY created_at DESC LIMIT 200"
  ).all(id);

  res.json({ task, logs });
});

app.patch("/api/tasks/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "not_found" });

  const body = req.body ?? {};
  const allowedFields = [
    "title", "description", "department_id", "assigned_agent_id",
    "status", "priority", "task_type", "project_path", "result",
  ];

  const updates: string[] = ["updated_at = ?"];
  const params: unknown[] = [nowMs()];

  for (const field of allowedFields) {
    if (field in body) {
      updates.push(`${field} = ?`);
      params.push(body[field]);
    }
  }

  // Handle completed_at for status changes
  if (body.status === "done" && !("completed_at" in body)) {
    updates.push("completed_at = ?");
    params.push(nowMs());
  }
  if (body.status === "in_progress" && !("started_at" in body)) {
    updates.push("started_at = ?");
    params.push(nowMs());
  }

  params.push(id);
  db.prepare(`UPDATE tasks SET ${updates.join(", ")} WHERE id = ?`).run(...params);

  appendTaskLog(id, "system", `Task updated: ${Object.keys(body).join(", ")}`);

  const updated = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updated);
  res.json({ ok: true, task: updated });
});

app.delete("/api/tasks/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    assigned_agent_id: string | null;
  } | undefined;
  if (!existing) return res.status(404).json({ error: "not_found" });

  // Kill any running process
  const activeChild = activeProcesses.get(id);
  if (activeChild?.pid) {
    killPidTree(activeChild.pid);
    activeProcesses.delete(id);
  }

  // Reset agent if assigned
  if (existing.assigned_agent_id) {
    db.prepare(
      "UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ? AND current_task_id = ?"
    ).run(existing.assigned_agent_id, id);
  }

  db.prepare("DELETE FROM task_logs WHERE task_id = ?").run(id);
  db.prepare("DELETE FROM messages WHERE task_id = ?").run(id);
  db.prepare("DELETE FROM tasks WHERE id = ?").run(id);

  // Clean up log files
  for (const suffix of [".log", ".prompt.txt"]) {
    const filePath = path.join(logsDir, `${id}${suffix}`);
    try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch { /* ignore */ }
  }

  broadcast("task_update", { id, deleted: true });
  res.json({ ok: true });
});

app.post("/api/tasks/:id/assign", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    assigned_agent_id: string | null;
    title: string;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  const agentId = req.body?.agent_id;
  if (!agentId || typeof agentId !== "string") {
    return res.status(400).json({ error: "agent_id_required" });
  }

  const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as {
    id: string;
    name: string;
    department_id: string | null;
  } | undefined;
  if (!agent) return res.status(404).json({ error: "agent_not_found" });

  const t = nowMs();

  // Unassign previous agent if different
  if (task.assigned_agent_id && task.assigned_agent_id !== agentId) {
    db.prepare(
      "UPDATE agents SET current_task_id = NULL WHERE id = ? AND current_task_id = ?"
    ).run(task.assigned_agent_id, id);
  }

  // Update task
  db.prepare(
    "UPDATE tasks SET assigned_agent_id = ?, department_id = COALESCE(department_id, ?), status = CASE WHEN status = 'inbox' THEN 'planned' ELSE status END, updated_at = ? WHERE id = ?"
  ).run(agentId, agent.department_id, t, id);

  // Update agent
  db.prepare("UPDATE agents SET current_task_id = ? WHERE id = ?").run(id, agentId);

  appendTaskLog(id, "system", `Assigned to agent: ${agent.name}`);

  // Create assignment message
  const msgId = randomUUID();
  db.prepare(
    `INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
     VALUES (?, 'ceo', NULL, 'agent', ?, ?, 'task_assign', ?, ?)`
  ).run(msgId, agentId, `New task assigned: ${task.title}`, id, t);

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId);

  broadcast("task_update", updatedTask);
  broadcast("agent_status", updatedAgent);
  broadcast("new_message", {
    id: msgId,
    sender_type: "ceo",
    receiver_type: "agent",
    receiver_id: agentId,
    content: `New task assigned: ${task.title}`,
    message_type: "task_assign",
    task_id: id,
    created_at: t,
  });

  // B4: Notify CEO about assignment via team leader
  const leader = findTeamLeader(agent.department_id);
  if (leader) {
    const agentRow = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
    const agentName = agentRow?.name_ko || agent.name;
    sendAgentMessage(
      leader,
      `${leader.name_ko || leader.name}이(가) ${agentName}에게 '${task.title}' 업무를 할당했습니다.`,
      "status_update",
      "all",
      null,
      id,
    );
  }

  res.json({ ok: true, task: updatedTask, agent: updatedAgent });
});

app.post("/api/tasks/:id/run", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    title: string;
    description: string | null;
    assigned_agent_id: string | null;
    project_path: string | null;
    status: string;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  if (task.status === "in_progress") {
    return res.status(400).json({ error: "already_running" });
  }

  // Get the agent (or use provided agent_id)
  const agentId = task.assigned_agent_id || (req.body?.agent_id as string | undefined);
  if (!agentId) {
    return res.status(400).json({ error: "no_agent_assigned", message: "Assign an agent before running." });
  }

  const agent = db.prepare(`
    SELECT a.*, d.name AS department_name, d.name_ko AS department_name_ko
    FROM agents a LEFT JOIN departments d ON a.department_id = d.id
    WHERE a.id = ?
  `).get(agentId) as {
    id: string;
    name: string;
    name_ko: string | null;
    role: string;
    cli_provider: string | null;
    personality: string | null;
    department_id: string | null;
    department_name: string | null;
    department_name_ko: string | null;
  } | undefined;
  if (!agent) return res.status(400).json({ error: "agent_not_found" });

  // Guard: agent already working on another task
  const agentBusy = activeProcesses.has(
    (db.prepare("SELECT current_task_id FROM agents WHERE id = ? AND status = 'working'").get(agentId) as { current_task_id: string | null } | undefined)?.current_task_id ?? ""
  );
  if (agentBusy) {
    return res.status(400).json({ error: "agent_busy", message: `${agent.name} is already working on another task.` });
  }

  const provider = agent.cli_provider || "claude";
  if (!["claude", "codex", "gemini", "opencode"].includes(provider)) {
    return res.status(400).json({ error: "unsupported_provider", provider });
  }

  const projectPath = resolveProjectPath(task) || (req.body?.project_path as string | undefined) || process.cwd();
  const logPath = path.join(logsDir, `${id}.log`);

  // Try to create a Git worktree for agent isolation
  const worktreePath = createWorktree(projectPath, id, agent.name);
  const agentCwd = worktreePath || projectPath;

  if (worktreePath) {
    appendTaskLog(id, "system", `Git worktree created: ${worktreePath} (branch: climpire/${id.slice(0, 8)})`);
  }

  // Build rich prompt with agent context + conversation history + role constraint
  const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[agent.role] || agent.role;
  const deptConstraint = agent.department_id ? getDeptRoleConstraint(agent.department_id, agent.department_name || agent.department_id) : "";
  const conversationCtx = getRecentConversationContext(agentId);
  const prompt = [
    `[Task] ${task.title}`,
    task.description ? `\n${task.description}` : "",
    conversationCtx,
    `\n---`,
    `Agent: ${agent.name} (${roleLabel}, ${agent.department_name || "Unassigned"})`,
    agent.personality ? `Personality: ${agent.personality}` : "",
    deptConstraint,
    worktreePath ? `NOTE: You are working in an isolated Git worktree branch (climpire/${id.slice(0, 8)}). Commit your changes normally.` : "",
    `Please complete the task above thoroughly. Use the conversation context above if relevant.`,
  ].filter(Boolean).join("\n");

  appendTaskLog(id, "system", `RUN start (agent=${agent.name}, provider=${provider})`);

  const child = spawnCliAgent(id, provider, prompt, agentCwd, logPath);

  child.on("close", (code) => {
    handleTaskRunComplete(id, code ?? 1);
  });

  const t = nowMs();

  // Update task status
  db.prepare(
    "UPDATE tasks SET status = 'in_progress', assigned_agent_id = ?, started_at = ?, updated_at = ? WHERE id = ?"
  ).run(agentId, t, t, id);

  // Update agent status
  db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(id, agentId);

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId);
  broadcast("task_update", updatedTask);
  broadcast("agent_status", updatedAgent);

  // B4: Notify CEO that task started
  const worktreeNote = worktreePath ? ` (격리 브랜치: climpire/${id.slice(0, 8)})` : "";
  notifyCeo(`${agent.name_ko || agent.name}가 '${task.title}' 작업을 시작했습니다.${worktreeNote}`, id);

  // B2: Start progress report timer for long-running tasks
  const taskRow = db.prepare("SELECT department_id FROM tasks WHERE id = ?").get(id) as { department_id: string | null } | undefined;
  startProgressTimer(id, task.title, taskRow?.department_id ?? null);

  res.json({ ok: true, pid: child.pid ?? null, logPath, cwd: agentCwd, worktree: !!worktreePath });
});

app.post("/api/tasks/:id/stop", (req, res) => {
  const id = String(req.params.id);
  // mode=pause → pending (can resume), mode=cancel or default → cancelled
  const mode = String(req.body?.mode ?? req.query.mode ?? "cancel");
  const targetStatus = mode === "pause" ? "pending" : "cancelled";

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    title: string;
    assigned_agent_id: string | null;
    department_id: string | null;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  stopProgressTimer(id);

  const activeChild = activeProcesses.get(id);
  if (!activeChild?.pid) {
    // No active process; just update status
    db.prepare("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?").run(targetStatus, nowMs(), id);
    if (task.assigned_agent_id) {
      db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?").run(task.assigned_agent_id);
    }
    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
    broadcast("task_update", updatedTask);
    return res.json({ ok: true, stopped: false, status: targetStatus, message: "No active process found." });
  }

  killPidTree(activeChild.pid);
  activeProcesses.delete(id);

  const actionLabel = targetStatus === "pending" ? "PAUSE" : "STOP";
  appendTaskLog(id, "system", `${actionLabel} sent to pid ${activeChild.pid}`);

  const t = nowMs();
  db.prepare("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?").run(targetStatus, t, id);

  if (task.assigned_agent_id) {
    db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?").run(task.assigned_agent_id);
    const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(task.assigned_agent_id);
    broadcast("agent_status", updatedAgent);
  }

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updatedTask);

  // CEO notification
  if (targetStatus === "pending") {
    notifyCeo(`'${task.title}' 작업이 보류 상태로 전환되었습니다.`, id);
  } else {
    notifyCeo(`'${task.title}' 작업이 취소되었습니다.`, id);
  }

  res.json({ ok: true, stopped: true, status: targetStatus, pid: activeChild.pid });
});

// Resume a pending or cancelled task → move back to planned (ready to re-run)
app.post("/api/tasks/:id/resume", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    title: string;
    status: string;
    assigned_agent_id: string | null;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  if (task.status !== "pending" && task.status !== "cancelled") {
    return res.status(400).json({ error: "invalid_status", message: `Cannot resume from '${task.status}'` });
  }

  const targetStatus = task.assigned_agent_id ? "planned" : "inbox";
  const t = nowMs();
  db.prepare("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?").run(targetStatus, t, id);

  appendTaskLog(id, "system", `RESUME: ${task.status} → ${targetStatus}`);

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updatedTask);

  notifyCeo(`'${task.title}' 작업이 복구되었습니다. (${targetStatus})`, id);

  res.json({ ok: true, status: targetStatus });
});

// ---------------------------------------------------------------------------
// Agent auto-reply & task delegation logic
// ---------------------------------------------------------------------------
interface AgentRow {
  id: string;
  name: string;
  name_ko: string;
  role: string;
  personality: string | null;
  status: string;
  department_id: string | null;
  current_task_id: string | null;
  avatar_emoji: string;
  cli_provider: string | null;
}

const ROLE_PRIORITY: Record<string, number> = {
  team_leader: 0, senior: 1, junior: 2, intern: 3,
};

const ROLE_LABEL: Record<string, string> = {
  team_leader: "팀장", senior: "시니어", junior: "주니어", intern: "인턴",
};

const DEPT_KEYWORDS: Record<string, string[]> = {
  dev:        ["개발", "코딩", "프론트", "백엔드", "API", "서버", "코드", "버그", "프로그램", "앱", "웹"],
  design:     ["디자인", "UI", "UX", "목업", "피그마", "아이콘", "로고", "배너", "레이아웃", "시안"],
  planning:   ["기획", "전략", "분석", "리서치", "보고서", "PPT", "발표", "시장", "조사", "제안"],
  operations: ["운영", "배포", "인프라", "모니터링", "서버관리", "CI", "CD", "DevOps", "장애"],
  qa:         ["QA", "QC", "품질", "테스트", "검수", "버그리포트", "회귀", "자동화테스트", "성능테스트", "리뷰"],
  devsecops:  ["보안", "취약점", "인증", "SSL", "방화벽", "해킹", "침투", "파이프라인", "컨테이너", "도커", "쿠버네티스", "암호화"],
};

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function sendAgentMessage(
  agent: AgentRow,
  content: string,
  messageType: string = "chat",
  receiverType: string = "agent",
  receiverId: string | null = null,
  taskId: string | null = null,
): void {
  const id = randomUUID();
  const t = nowMs();
  db.prepare(`
    INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
    VALUES (?, 'agent', ?, ?, ?, ?, ?, ?, ?)
  `).run(id, agent.id, receiverType, receiverId, content, messageType, taskId, t);

  broadcast("new_message", {
    id,
    sender_type: "agent",
    sender_id: agent.id,
    receiver_type: receiverType,
    receiver_id: receiverId,
    content,
    message_type: messageType,
    task_id: taskId,
    created_at: t,
    sender_name: agent.name,
    sender_avatar: agent.avatar_emoji ?? "🤖",
  });
}

// ---- Language detection & multilingual response system ----

type Lang = "ko" | "en" | "ja" | "zh";

function detectLang(text: string): Lang {
  const ko = text.match(/[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]/g)?.length ?? 0;
  const ja = text.match(/[\u3040-\u309F\u30A0-\u30FF]/g)?.length ?? 0;
  const zh = text.match(/[\u4E00-\u9FFF]/g)?.length ?? 0;
  const total = text.replace(/\s/g, "").length || 1;
  if (ko / total > 0.15) return "ko";
  if (ja / total > 0.15) return "ja";
  if (zh / total > 0.3) return "zh";
  return "en";
}

// Bilingual response templates: { ko, en, ja, zh }
type L10n = Record<Lang, string[]>;

function l(ko: string[], en: string[], ja?: string[], zh?: string[]): L10n {
  return {
    ko,
    en,
    ja: ja ?? en.map(s => s),  // fallback to English
    zh: zh ?? en.map(s => s),
  };
}

function pickL(pool: L10n, lang: Lang): string {
  const arr = pool[lang];
  return arr[Math.floor(Math.random() * arr.length)];
}

// Agent personality flair by agent name + language
function getFlairs(agentName: string, lang: Lang): string[] {
  const flairs: Record<string, Record<Lang, string[]>> = {
    Aria:  { ko: ["코드 리뷰 중에", "리팩토링 구상하면서", "PR 체크하면서"],
             en: ["reviewing code", "planning a refactor", "checking PRs"],
             ja: ["コードレビュー中に", "リファクタリングを考えながら", "PR確認しながら"],
             zh: ["审查代码中", "规划重构时", "检查PR时"] },
    Bolt:  { ko: ["빠르게 코딩하면서", "API 설계하면서", "성능 튜닝하면서"],
             en: ["coding fast", "designing APIs", "tuning performance"],
             ja: ["高速コーディング中", "API設計しながら", "パフォーマンスチューニング中"],
             zh: ["快速编码中", "设计API时", "调优性能时"] },
    Nova:  { ko: ["새로운 기술 공부하면서", "프로토타입 만들면서", "실험적인 코드 짜면서"],
             en: ["studying new tech", "building a prototype", "writing experimental code"],
             ja: ["新技術を勉強しながら", "プロトタイプ作成中", "実験的なコード書き中"],
             zh: ["学习新技术中", "制作原型时", "编写实验代码时"] },
    Pixel: { ko: ["디자인 시안 작업하면서", "컴포넌트 정리하면서", "UI 가이드 업데이트하면서"],
             en: ["working on mockups", "organizing components", "updating the UI guide"],
             ja: ["デザインモックアップ作業中", "コンポーネント整理しながら", "UIガイド更新中"],
             zh: ["制作设计稿中", "整理组件时", "更新UI指南时"] },
    Luna:  { ko: ["애니메이션 작업하면서", "컬러 팔레트 고민하면서", "사용자 경험 분석하면서"],
             en: ["working on animations", "refining the color palette", "analyzing UX"],
             ja: ["アニメーション作業中", "カラーパレット検討中", "UX分析しながら"],
             zh: ["制作动画中", "调整调色板时", "分析用户体验时"] },
    Sage:  { ko: ["시장 분석 보고서 보면서", "전략 문서 정리하면서", "경쟁사 리서치하면서"],
             en: ["reviewing market analysis", "organizing strategy docs", "researching competitors"],
             ja: ["市場分析レポート確認中", "戦略文書整理中", "競合リサーチしながら"],
             zh: ["查看市场分析报告", "整理战略文件时", "调研竞品时"] },
    Clio:  { ko: ["데이터 분석하면서", "기획서 작성하면서", "사용자 인터뷰 정리하면서"],
             en: ["analyzing data", "drafting a proposal", "organizing user interviews"],
             ja: ["データ分析中", "企画書作成中", "ユーザーインタビュー整理中"],
             zh: ["分析数据中", "撰写企划书时", "整理用户访谈时"] },
    Atlas: { ko: ["서버 모니터링하면서", "배포 파이프라인 점검하면서", "운영 지표 확인하면서"],
             en: ["monitoring servers", "checking deploy pipelines", "reviewing ops metrics"],
             ja: ["サーバー監視中", "デプロイパイプライン点検中", "運用指標確認中"],
             zh: ["监控服务器中", "检查部署流水线时", "查看运营指标时"] },
    Turbo: { ko: ["자동화 스크립트 돌리면서", "CI/CD 최적화하면서", "인프라 정리하면서"],
             en: ["running automation scripts", "optimizing CI/CD", "cleaning up infra"],
             ja: ["自動化スクリプト実行中", "CI/CD最適化中", "インフラ整理中"],
             zh: ["运行自动化脚本中", "优化CI/CD时", "整理基础设施时"] },
    Hawk:  { ko: ["테스트 케이스 리뷰하면서", "버그 리포트 분석하면서", "품질 지표 확인하면서"],
             en: ["reviewing test cases", "analyzing bug reports", "checking quality metrics"],
             ja: ["テストケースレビュー中", "バグレポート分析中", "品質指標確認中"],
             zh: ["审查测试用例中", "分析缺陷报告时", "查看质量指标时"] },
    Lint:  { ko: ["자동화 테스트 작성하면서", "코드 검수하면서", "회귀 테스트 돌리면서"],
             en: ["writing automated tests", "inspecting code", "running regression tests"],
             ja: ["自動テスト作成中", "コード検査中", "回帰テスト実行中"],
             zh: ["编写自动化测试中", "检查代码时", "运行回归测试时"] },
    Vault: { ko: ["보안 감사 진행하면서", "취약점 스캔 결과 보면서", "인증 로직 점검하면서"],
             en: ["running a security audit", "reviewing vuln scan results", "checking auth logic"],
             ja: ["セキュリティ監査中", "脆弱性スキャン結果確認中", "認証ロジック点検中"],
             zh: ["进行安全审计中", "查看漏洞扫描结果时", "检查认证逻辑时"] },
    Pipe:  { ko: ["파이프라인 구축하면서", "컨테이너 설정 정리하면서", "배포 자동화 하면서"],
             en: ["building pipelines", "configuring containers", "automating deployments"],
             ja: ["パイプライン構築中", "コンテナ設定整理中", "デプロイ自動化中"],
             zh: ["构建流水线中", "配置容器时", "自动化部署时"] },
  };
  const agentFlairs = flairs[agentName];
  if (agentFlairs) return agentFlairs[lang] ?? agentFlairs.en;
  const defaults: Record<Lang, string[]> = {
    ko: ["업무 처리하면서", "작업 진행하면서", "일하면서"],
    en: ["working on tasks", "making progress", "getting things done"],
    ja: ["業務処理中", "作業進行中", "仕事しながら"],
    zh: ["处理业务中", "推进工作时", "忙着干活时"],
  };
  return defaults[lang];
}

// Role labels per language
const ROLE_LABEL_L10N: Record<string, Record<Lang, string>> = {
  team_leader: { ko: "팀장", en: "Team Lead", ja: "チームリーダー", zh: "组长" },
  senior:      { ko: "시니어", en: "Senior", ja: "シニア", zh: "高级" },
  junior:      { ko: "주니어", en: "Junior", ja: "ジュニア", zh: "初级" },
  intern:      { ko: "인턴", en: "Intern", ja: "インターン", zh: "实习生" },
};

function getRoleLabel(role: string, lang: Lang): string {
  return ROLE_LABEL_L10N[role]?.[lang] ?? ROLE_LABEL[role] ?? role;
}

// Intent classifiers per language
function classifyIntent(msg: string, lang: Lang) {
  const checks: Record<string, RegExp[]> = {
    greeting: [
      /안녕|하이|반가|좋은\s*(아침|오후|저녁)/i,
      /hello|hi\b|hey|good\s*(morning|afternoon|evening)|howdy|what'?s\s*up/i,
      /こんにちは|おはよう|こんばんは|やあ|どうも/i,
      /你好|嗨|早上好|下午好|晚上好/i,
    ],
    presence: [
      /자리|있어|계세요|계신가|거기|응답|들려|보여|어디야|어딨/i,
      /are you (there|here|around|available|at your desk)|you there|anybody|present/i,
      /いますか|席に|いる？|応答/i,
      /在吗|在不在|有人吗/i,
    ],
    whatDoing: [
      /뭐\s*해|뭐하|뭘\s*해|뭐\s*하고|뭐\s*하는|하는\s*중|진행\s*중|바쁘|바빠|한가/i,
      /what are you (doing|up to|working on)|busy|free|what'?s going on|occupied/i,
      /何してる|忙しい|暇|何やってる/i,
      /在做什么|忙吗|有空吗|在干嘛/i,
    ],
    report: [
      /보고|현황|상태|진행|어디까지|결과|리포트|성과/i,
      /report|status|progress|update|how('?s| is) (it|the|your)|results/i,
      /報告|進捗|状況|ステータス/i,
      /报告|进度|状态|进展/i,
    ],
    praise: [
      /잘했|수고|고마|감사|훌륭|대단|멋져|최고|짱/i,
      /good (job|work)|well done|thank|great|awesome|amazing|excellent|nice|kudos|bravo/i,
      /よくやった|お疲れ|ありがとう|素晴らしい|すごい/i,
      /做得好|辛苦|谢谢|太棒了|厉害/i,
    ],
    encourage: [
      /힘내|화이팅|파이팅|응원|열심히|잘\s*부탁|잘\s*해|잘해봐/i,
      /keep (it )?up|go for it|fighting|you (got|can do) (this|it)|cheer|hang in there/i,
      /頑張|ファイト|応援/i,
      /加油|努力|拜托/i,
    ],
    joke: [
      /ㅋ|ㅎ|웃|재밌|장난|농담|심심|놀자/i,
      /lol|lmao|haha|joke|funny|bored|play/i,
      /笑|面白い|冗談|暇/i,
      /哈哈|笑|开玩笑|无聊/i,
    ],
    complaint: [
      /느려|답답|왜\s*이래|언제\s*돼|빨리|지연|늦/i,
      /slow|frustrat|why (is|so)|when (will|is)|hurry|delay|late|taking (too )?long/i,
      /遅い|イライラ|なぜ|いつ|急いで/i,
      /慢|着急|为什么|快点|延迟/i,
    ],
    opinion: [
      /어때|생각|의견|아이디어|제안|건의|어떨까|괜찮/i,
      /what do you think|opinion|idea|suggest|how about|thoughts|recommend/i,
      /どう思う|意見|アイデア|提案/i,
      /怎么看|意见|想法|建议/i,
    ],
    canDo: [
      /가능|할\s*수|되나|될까|할까|해줘|해\s*줄|맡아|부탁/i,
      /can you|could you|possible|able to|handle|take care|would you|please/i,
      /できる|可能|お願い|頼む|やって/i,
      /能不能|可以|拜托|帮忙|处理/i,
    ],
    question: [
      /\?|뭐|어디|언제|왜|어떻게|무엇|몇/i,
      /\?|what|where|when|why|how|which|who/i,
      /\?|何|どこ|いつ|なぜ|どう/i,
      /\?|什么|哪里|什么时候|为什么|怎么/i,
    ],
  };

  const langIdx = { ko: 0, en: 1, ja: 2, zh: 3 }[lang];
  const result: Record<string, boolean> = {};
  for (const [key, patterns] of Object.entries(checks)) {
    // Check ALL language patterns (user may mix languages)
    result[key] = patterns.some(p => p.test(msg));
  }
  return result;
}

function generateChatReply(agent: AgentRow, ceoMessage: string): string {
  const msg = ceoMessage.trim();
  const lang = detectLang(msg);
  const name = lang === "ko" ? (agent.name_ko || agent.name) : agent.name;
  const dept = agent.department_id ? getDeptName(agent.department_id) : "";
  const role = getRoleLabel(agent.role, lang);
  const nameTag = dept ? (lang === "ko" ? `${dept} ${role} ${name}` : `${name}, ${role} of ${dept}`) : `${role} ${name}`;
  const flairs = getFlairs(agent.name, lang);
  const flair = () => pickRandom(flairs);
  const intent = classifyIntent(msg, lang);

  // Current task info
  let taskTitle = "";
  if (agent.current_task_id) {
    const t = db.prepare("SELECT title FROM tasks WHERE id = ?").get(agent.current_task_id) as { title: string } | undefined;
    if (t) taskTitle = t.title;
  }

  // ---- Offline ----
  if (agent.status === "offline") return pickL(l(
    [`[자동응답] ${nameTag}은(는) 현재 오프라인입니다. 복귀 후 확인하겠습니다.`],
    [`[Auto-reply] ${name} is currently offline. I'll check when I'm back.`],
    [`[自動応答] ${name}は現在オフラインです。復帰後確認します。`],
    [`[自动回复] ${name}目前离线，回来后会确认。`],
  ), lang);

  // ---- Break ----
  if (agent.status === "break") {
    if (intent.presence) return pickL(l(
      [`앗, 대표님! 잠깐 커피 타러 갔었습니다. 바로 자리 복귀했습니다! ☕`, `네! 휴식 중이었는데 돌아왔습니다. 무슨 일이신가요?`, `여기 있습니다! 잠시 환기하고 왔어요. 말씀하세요~ 😊`],
      [`Oh! I just stepped out for coffee. I'm back now! ☕`, `Yes! I was on a short break but I'm here. What do you need?`, `I'm here! Just took a quick breather. What's up? 😊`],
      [`あ、少し休憩していました！戻りました！☕`, `はい！少し休んでいましたが、戻りました。何でしょう？`],
      [`啊，刚去倒了杯咖啡。回来了！☕`, `在的！刚休息了一下，有什么事吗？`],
    ), lang);
    if (intent.greeting) return pickL(l(
      [`안녕하세요, 대표님! 잠깐 쉬고 있었는데, 말씀하세요! ☕`, `네~ 대표님! ${name}입니다. 잠시 브레이크 중이었어요. 무슨 일이세요?`],
      [`Hi! I was on a quick break. How can I help? ☕`, `Hey! ${name} here. Was taking a breather. What's going on?`],
      [`こんにちは！少し休憩中でした。何でしょう？☕`],
      [`你好！我刚在休息。有什么事吗？☕`],
    ), lang);
    return pickL(l(
      [`앗, 잠시 쉬고 있었습니다! 바로 확인하겠습니다 😅`, `네, 대표님! 휴식 끝내고 바로 보겠습니다!`, `복귀했습니다! 말씀하신 건 바로 처리할게요 ☕`],
      [`Oh, I was taking a break! Let me check right away 😅`, `Got it! Break's over, I'll look into it now!`, `I'm back! I'll handle that right away ☕`],
      [`あ、休憩中でした！すぐ確認します 😅`, `戻りました！すぐ対応します ☕`],
      [`啊，刚在休息！马上看 😅`, `回来了！马上处理 ☕`],
    ), lang);
  }

  // ---- Working ----
  if (agent.status === "working") {
    const taskKo = taskTitle ? ` "${taskTitle}" 작업` : " 할당된 업무";
    const taskEn = taskTitle ? ` "${taskTitle}"` : " my current task";
    const taskJa = taskTitle ? ` "${taskTitle}"` : " 現在のタスク";
    const taskZh = taskTitle ? ` "${taskTitle}"` : " 当前任务";

    if (intent.presence) return pickL(l(
      [`네! 자리에 있습니다. 지금${taskKo} 진행 중이에요. 말씀하세요!`, `여기 있습니다, 대표님! ${flair()} 열심히 하고 있어요 💻`, `네~ 자리에서${taskKo} 처리 중입니다. 무슨 일이세요?`],
      [`Yes! I'm here. Currently working on${taskEn}. What do you need?`, `I'm at my desk! ${flair()} and making good progress 💻`, `Right here! Working on${taskEn}. What's up?`],
      [`はい！席にいます。${taskJa}を進行中です。何でしょう？`, `ここにいますよ！${flair()}頑張っています 💻`],
      [`在的！正在处理${taskZh}。有什么事？`, `我在工位上！正在${flair()} 💻`],
    ), lang);
    if (intent.greeting) return pickL(l(
      [`안녕하세요, 대표님! ${nameTag}입니다. ${flair()} 작업 중이에요 😊`, `네, 대표님! 지금${taskKo}에 집중 중인데, 말씀하세요!`],
      [`Hi! ${nameTag} here. Currently ${flair()} 😊`, `Hello! I'm focused on${taskEn} right now, but go ahead!`],
      [`こんにちは！${name}です。${flair()}作業中です 😊`],
      [`你好！${name}在这。正在${flair()} 😊`],
    ), lang);
    if (intent.whatDoing) return pickL(l(
      [`지금${taskKo} 진행 중입니다! ${flair()} 순조롭게 되고 있어요 📊`, `${flair()}${taskKo} 처리하고 있습니다. 70% 정도 진행됐어요!`, `현재${taskKo}에 몰두 중입니다. 곧 완료될 것 같아요! 💪`],
      [`Working on${taskEn} right now! ${flair()} — going smoothly 📊`, `I'm ${flair()} on${taskEn}. About 70% done!`, `Deep into${taskEn} at the moment. Should be done soon! 💪`],
      [`${taskJa}を進行中です！${flair()}順調です 📊`, `${flair()}${taskJa}に取り組んでいます。もうすぐ完了です！💪`],
      [`正在处理${taskZh}！${flair()}进展顺利 📊`, `${flair()}处理${taskZh}中，大概完成70%了！💪`],
    ), lang);
    if (intent.report) return pickL(l(
      [`${taskKo} 순조롭게 진행되고 있습니다. ${flair()} 마무리 단계에요! 📊`, `현재${taskKo} 진행률 약 70%입니다. 예정대로 완료 가능할 것 같습니다!`],
      [`${taskEn} is progressing well. ${flair()} — wrapping up! 📊`, `About 70% done on${taskEn}. On track for completion!`],
      [`${taskJa}は順調に進んでいます。${flair()}まもなく完了です！📊`],
      [`${taskZh}进展顺利。${flair()}快收尾了！📊`],
    ), lang);
    if (intent.complaint) return pickL(l(
      [`죄송합니다, 대표님. 최대한 속도 내서 처리하겠습니다! 🏃‍♂️`, `빠르게 진행하고 있습니다! 조금만 더 시간 주시면 곧 마무리됩니다.`],
      [`Sorry about that! I'll pick up the pace 🏃‍♂️`, `Working as fast as I can! Just need a bit more time.`],
      [`申し訳ありません！最速で対応します 🏃‍♂️`],
      [`抱歉！我会加快速度 🏃‍♂️`],
    ), lang);
    if (intent.canDo) return pickL(l(
      [`지금 작업 중이라 바로는 어렵지만, 완료 후 바로 착수하겠습니다! 📝`, `현 작업 마무리되면 바로 가능합니다! 메모해두겠습니다.`],
      [`I'm tied up right now, but I'll jump on it as soon as I finish! 📝`, `Can do! Let me wrap up my current task first.`],
      [`今は作業中ですが、完了後すぐ取りかかります！📝`],
      [`现在在忙，完成后马上开始！📝`],
    ), lang);
    return pickL(l(
      [`네, 확인했습니다! 현재 작업 마무리 후 확인하겠습니다 📝`, `알겠습니다, 대표님. ${flair()} 일단 메모해두겠습니다!`],
      [`Got it! I'll check after finishing my current task 📝`, `Noted! I'll get to it once I'm done here.`],
      [`了解しました！現在の作業完了後に確認します 📝`],
      [`收到！完成当前工作后确认 📝`],
    ), lang);
  }

  // ---- Idle (default) ----

  if (intent.presence) return pickL(l(
    [`네! 자리에 있습니다, 대표님. ${nameTag}입니다. 말씀하세요! 😊`, `여기 있어요! 대기 중이었습니다. 무슨 일이세요?`, `네~ 자리에 있습니다! 업무 지시 기다리고 있었어요.`, `항상 대기 중입니다, 대표님! ${name} 여기 있어요 ✋`],
    [`Yes, I'm here! ${nameTag}. What do you need? 😊`, `Right here! I was on standby. What's up?`, `I'm at my desk! Ready for anything.`, `Always ready! ${name} is here ✋`],
    [`はい！席にいます。${name}です。何でしょう？😊`, `ここにいますよ！待機中でした。`, `席にいます！指示をお待ちしています ✋`],
    [`在的！${name}在这。有什么事吗？😊`, `我在！一直待命中。有什么需要？`, `随时准备就绪！${name}在这 ✋`],
  ), lang);
  if (intent.greeting) return pickL(l(
    [`안녕하세요, 대표님! ${nameTag}입니다. 오늘도 좋은 하루 보내고 계신가요? 😊`, `안녕하세요! ${nameTag}입니다. 필요하신 게 있으시면 편하게 말씀하세요!`, `네, 대표님! ${name}입니다. 오늘도 파이팅이요! 🔥`, `반갑습니다, 대표님! ${dept} ${name}, 준비 완료입니다!`],
    [`Hello! ${nameTag} here. Having a good day? 😊`, `Hi! ${nameTag}. Feel free to let me know if you need anything!`, `Hey! ${name} here. Let's make today count! 🔥`, `Good to see you! ${name} from ${dept}, ready to go!`],
    [`こんにちは！${name}です。今日もよろしくお願いします 😊`, `${name}です。何かあればお気軽にどうぞ！`, `今日も頑張りましょう！🔥`],
    [`你好！${name}在这。今天也加油！😊`, `${name}随时准备好了，有什么需要请说！🔥`],
  ), lang);
  if (intent.whatDoing) return pickL(l(
    [`지금은 대기 중이에요! ${flair()} 스킬업 하고 있었습니다 📚`, `특별한 업무는 없어서 ${flair()} 개인 학습 중이었어요.`, `한가한 상태입니다! 새로운 업무 주시면 바로 착수할 수 있어요 🙌`],
    [`I'm on standby! Was ${flair()} to sharpen my skills 📚`, `Nothing assigned right now, so I was ${flair()}.`, `I'm free! Give me something to do and I'll jump right in 🙌`],
    [`待機中です！${flair()}スキルアップしていました 📚`, `特に業務はないので、${flair()}個人学習中でした。`],
    [`待命中！正在${flair()}提升技能 📚`, `没有特别的任务，正在${flair()}学习中。`],
  ), lang);
  if (intent.praise) return pickL(l(
    [`감사합니다, 대표님! 더 열심히 하겠습니다! 💪`, `대표님 칭찬에 힘이 불끈! 오늘도 최선을 다할게요 😊`, `앗, 감사합니다~ 대표님이 알아주시니 더 보람차네요! ✨`],
    [`Thank you! I'll keep up the great work! 💪`, `That means a lot! I'll do my best 😊`, `Thanks! Really motivating to hear that ✨`],
    [`ありがとうございます！もっと頑張ります！💪`, `嬉しいです！最善を尽くします 😊`],
    [`谢谢！会继续努力的！💪`, `太开心了！会做到最好 😊`],
  ), lang);
  if (intent.encourage) return pickL(l(
    [`감사합니다! 대표님 응원 덕분에 힘이 납니다! 💪`, `네! 화이팅입니다! 기대에 꼭 부응할게요 🔥`],
    [`Thanks! Your support means everything! 💪`, `You got it! I won't let you down 🔥`],
    [`ありがとうございます！頑張ります！💪`, `期待に応えます！🔥`],
    [`谢谢鼓励！一定不辜负期望！💪🔥`],
  ), lang);
  if (intent.report) return pickL(l(
    [`현재 대기 상태이고, 할당된 업무는 없습니다. 새 업무 주시면 바로 시작할 수 있어요! 📋`, `대기 중이라 여유 있습니다. 업무 지시 기다리고 있어요!`],
    [`Currently on standby with no assigned tasks. Ready to start anything! 📋`, `I'm available! Just waiting for the next assignment.`],
    [`現在待機中で、割り当てタスクはありません。いつでも開始できます！📋`],
    [`目前待命中，没有分配任务。随时可以开始！📋`],
  ), lang);
  if (intent.joke) return pickL(l(
    [`ㅎㅎ 대표님 오늘 기분 좋으신가 봐요! 😄`, `ㅋㅋ 대표님이랑 일하면 분위기가 좋아요~`, `😂 잠깐 웃고 다시 집중! 업무 주시면 바로 달리겠습니다!`],
    [`Haha, you're in a good mood today! 😄`, `Love the vibes! Working with you is always fun~`, `😂 Good laugh! Alright, ready to get back to work!`],
    [`ハハ、今日はいい気分ですね！😄`, `😂 いい雰囲気！仕事に戻りましょう！`],
    [`哈哈，今天心情不错啊！😄`, `😂 笑完了，准备干活！`],
  ), lang);
  if (intent.complaint) return pickL(l(
    [`죄송합니다, 대표님! 더 빠르게 움직이겠습니다.`, `말씀 새겨듣겠습니다. 개선해서 보여드리겠습니다! 🙏`],
    [`Sorry about that! I'll step it up.`, `I hear you. I'll improve and show results! 🙏`],
    [`申し訳ありません！もっと速く動きます。`, `改善してお見せします！🙏`],
    [`抱歉！会加快行动。`, `记住了，会改进的！🙏`],
  ), lang);
  if (intent.opinion) return pickL(l(
    [`제 의견으로는요... ${dept} 관점에서 한번 검토해보겠습니다! 🤔`, `좋은 질문이시네요! 관련해서 정리해서 말씀드릴게요.`, `${dept}에서 보기엔 긍정적으로 보입니다. 자세한 내용 분석 후 말씀드릴게요 📊`],
    [`From a ${dept} perspective, let me think about that... 🤔`, `Great question! Let me put together my thoughts on this.`, `Looks promising from where I sit. I'll analyze the details and get back to you 📊`],
    [`${dept}の観点から検討してみます！🤔`, `いい質問ですね！整理してお伝えします。`],
    [`从${dept}角度看，让我想想... 🤔`, `好问题！我整理一下想法再回复您 📊`],
  ), lang);
  if (intent.canDo) return pickL(l(
    [`물론이죠! 바로 시작할 수 있습니다. 상세 내용 말씀해주세요! 🚀`, `가능합니다, 대표님! 지금 여유 있으니 바로 착수하겠습니다.`, `네, 맡겨주세요! ${name}이(가) 책임지고 처리하겠습니다 💪`],
    [`Absolutely! I can start right away. Just give me the details! 🚀`, `Can do! I'm free right now, so I'll get on it.`, `Leave it to me! ${name} will handle it 💪`],
    [`もちろんです！すぐ始められます。詳細を教えてください！🚀`, `お任せください！${name}が責任持って対応します 💪`],
    [`当然可以！马上开始。请告诉我详情！🚀`, `交给我吧！${name}负责处理 💪`],
  ), lang);
  if (intent.question) return pickL(l(
    [`확인해보겠습니다! 잠시만요 🔍`, `음, 좋은 질문이시네요. 찾아보고 말씀드리겠습니다!`, `관련 내용 파악해서 빠르게 답변 드리겠습니다.`],
    [`Let me check on that! One moment 🔍`, `Good question! Let me look into it and get back to you.`, `I'll find out and get back to you ASAP.`],
    [`確認してみます！少々お待ちください 🔍`, `いい質問ですね。調べてお伝えします！`],
    [`让我查一下！稍等 🔍`, `好问题！我查查看。`],
  ), lang);
  return pickL(l(
    [`네, 확인했습니다! 추가로 필요하신 게 있으면 말씀해주세요.`, `네! ${name} 잘 들었습니다 😊 지시사항 있으시면 편하게 말씀하세요.`, `알겠습니다, 대표님! 관련해서 진행할게요.`, `확인했습니다! 바로 반영하겠습니다 📝`],
    [`Got it! Let me know if you need anything else.`, `Understood! ${name} is on it 😊`, `Roger that! I'll get moving on this.`, `Noted! I'll take care of it 📝`],
    [`了解しました！他に必要なことがあればお知らせください。`, `承知しました！${name}が対応します 😊`, `かしこまりました！すぐ対応します 📝`],
    [`收到！有其他需要随时说。`, `明白了！${name}这就去办 😊`, `了解！马上处理 📝`],
  ), lang);
}

// ---- Announcement reply logic (team leaders respond) ----

function generateAnnouncementReply(agent: AgentRow, announcement: string, lang: Lang): string {
  const name = lang === "ko" ? (agent.name_ko || agent.name) : agent.name;
  const dept = agent.department_id ? getDeptName(agent.department_id) : "";
  const role = getRoleLabel(agent.role, lang);

  // Detect announcement type
  const isUrgent = /긴급|중요|즉시|urgent|important|immediately|critical|緊急|紧急/i.test(announcement);
  const isGoodNews = /축하|달성|성공|감사|congrat|achieve|success|thank|おめでとう|祝贺|恭喜/i.test(announcement);
  const isPolicy = /정책|방침|규칙|변경|policy|change|rule|update|方針|政策/i.test(announcement);
  const isMeeting = /회의|미팅|모임|meeting|gather|会議|开会/i.test(announcement);

  if (isUrgent) return pickL(l(
    [`${dept} ${name}, 확인했습니다! 즉시 팀에 전달하고 대응하겠습니다! 🚨`, `네, 긴급 확인! ${dept}에서 바로 조치 취하겠습니다.`, `${name} 확인했습니다! 팀원들에게 즉시 공유하겠습니다.`],
    [`${name} from ${dept} — acknowledged! I'll relay this to my team immediately! 🚨`, `Urgent noted! ${dept} is on it right away.`, `${name} here — confirmed! Sharing with the team ASAP.`],
    [`${dept}の${name}、確認しました！チームにすぐ伝達します！🚨`],
    [`${dept}${name}收到！立即传达给团队！🚨`],
  ), lang);
  if (isGoodNews) return pickL(l(
    [`축하합니다! ${dept}도 함께 기뻐요! 🎉`, `좋은 소식이네요! ${dept} 팀원들에게도 공유하겠습니다 😊`, `${name} 확인! 정말 좋은 소식입니다! 👏`],
    [`Congratulations! ${dept} is thrilled! 🎉`, `Great news! I'll share this with my team 😊`, `${name} here — wonderful to hear! 👏`],
    [`おめでとうございます！${dept}も喜んでいます！🎉`],
    [`恭喜！${dept}也很高兴！🎉`],
  ), lang);
  if (isMeeting) return pickL(l(
    [`${dept} ${name}, 확인했습니다! 일정 잡아두겠습니다 📅`, `네, 참석하겠습니다! ${dept} 팀원들에게도 전달할게요.`, `${name} 확인! 미팅 준비하겠습니다.`],
    [`${name} from ${dept} — noted! I'll block the time 📅`, `Will be there! I'll let my team know too.`, `${name} confirmed! I'll prepare for the meeting.`],
    [`${name}確認しました！スケジュール押さえます 📅`],
    [`${name}收到！会安排时间 📅`],
  ), lang);
  if (isPolicy) return pickL(l(
    [`${dept} ${name}, 확인했습니다. 팀 내 공유하고 반영하겠습니다 📋`, `네, 정책 변경 확인! ${dept}에서 필요한 조치 검토하겠습니다.`],
    [`${name} from ${dept} — understood. I'll share with the team and align accordingly 📋`, `Policy update noted! ${dept} will review and adjust.`],
    [`${name}確認しました。チーム内に共有し反映します 📋`],
    [`${name}收到，会在团队内传达并落实 📋`],
  ), lang);
  // Generic
  return pickL(l(
    [`${dept} ${name}, 확인했습니다! 👍`, `네, 공지 확인! ${dept}에서 참고하겠습니다.`, `${name} 확인했습니다. 팀에 공유하겠습니다!`, `알겠습니다! ${dept} 업무에 반영하겠습니다 📝`],
    [`${name} from ${dept} — acknowledged! 👍`, `Noted! ${dept} will take this into account.`, `${name} here — confirmed. I'll share with the team!`, `Got it! We'll factor this into ${dept}'s work 📝`],
    [`${dept}の${name}、確認しました！👍`, `承知しました！チームに共有します！`],
    [`${dept}${name}收到！👍`, `明白了！会传达给团队！`],
  ), lang);
}

function scheduleAnnouncementReplies(announcement: string): void {
  const lang = detectLang(announcement);
  const teamLeaders = db.prepare(
    "SELECT * FROM agents WHERE role = 'team_leader' AND status != 'offline'"
  ).all() as AgentRow[];

  let delay = 1500; // First reply after 1.5s
  for (const leader of teamLeaders) {
    const replyDelay = delay + Math.random() * 1500; // stagger each leader by 1.5-3s
    setTimeout(() => {
      const reply = generateAnnouncementReply(leader, announcement, lang);
      sendAgentMessage(leader, reply, "chat", "all", null, null);
    }, replyDelay);
    delay += 1500 + Math.random() * 1500;
  }
}

// ---- Task delegation logic for team leaders ----

function detectTargetDepartments(message: string): string[] {
  const found: string[] = [];
  for (const [deptId, keywords] of Object.entries(DEPT_KEYWORDS)) {
    for (const kw of keywords) {
      if (message.includes(kw)) { found.push(deptId); break; }
    }
  }
  return found;
}

/** Detect @mentions in messages — returns department IDs and agent IDs */
function detectMentions(message: string): { deptIds: string[]; agentIds: string[] } {
  const deptIds: string[] = [];
  const agentIds: string[] = [];

  // Match @부서이름 patterns (both with and without 팀 suffix)
  const depts = db.prepare("SELECT id, name, name_ko FROM departments").all() as { id: string; name: string; name_ko: string }[];
  for (const dept of depts) {
    const nameKo = dept.name_ko.replace("팀", "");
    if (
      message.includes(`@${dept.name_ko}`) ||
      message.includes(`@${nameKo}`) ||
      message.includes(`@${dept.name}`) ||
      message.includes(`@${dept.id}`)
    ) {
      deptIds.push(dept.id);
    }
  }

  // Match @에이전트이름 patterns
  const agents = db.prepare("SELECT id, name, name_ko FROM agents").all() as { id: string; name: string; name_ko: string | null }[];
  for (const agent of agents) {
    if (
      (agent.name_ko && message.includes(`@${agent.name_ko}`)) ||
      message.includes(`@${agent.name}`)
    ) {
      agentIds.push(agent.id);
    }
  }

  return { deptIds, agentIds };
}

/** Handle mention-based delegation: create task in mentioned department */
function handleMentionDelegation(
  originLeader: AgentRow,
  targetDeptId: string,
  ceoMessage: string,
  lang: string,
): void {
  const crossLeader = findTeamLeader(targetDeptId);
  if (!crossLeader) return;
  const crossDeptName = getDeptName(targetDeptId);
  const crossLeaderName = lang === "ko" ? (crossLeader.name_ko || crossLeader.name) : crossLeader.name;
  const originLeaderName = lang === "ko" ? (originLeader.name_ko || originLeader.name) : originLeader.name;
  const taskTitle = ceoMessage.length > 60 ? ceoMessage.slice(0, 57) + "..." : ceoMessage;

  // Origin team leader sends mention request to target team leader
  const mentionReq = pickL(l(
    [`${crossLeaderName}님! 대표님 지시입니다: "${taskTitle}" — ${crossDeptName}에서 처리 부탁드립니다! 🏷️`, `${crossLeaderName}님, 대표님이 직접 요청하셨습니다. "${taskTitle}" 건, ${crossDeptName} 담당으로 진행해주세요!`],
    [`${crossLeaderName}! CEO directive for ${crossDeptName}: "${taskTitle}" — please handle this! 🏷️`, `${crossLeaderName}, CEO requested this for your team: "${taskTitle}"`],
    [`${crossLeaderName}さん！CEO指示です："${taskTitle}" — ${crossDeptName}で対応お願いします！🏷️`],
    [`${crossLeaderName}，CEO指示："${taskTitle}" — 请${crossDeptName}处理！🏷️`],
  ), lang);
  sendAgentMessage(originLeader, mentionReq, "task_assign", "agent", crossLeader.id, null);

  // Broadcast delivery animation event for UI
  broadcast("cross_dept_delivery", {
    from_agent_id: originLeader.id,
    to_agent_id: crossLeader.id,
    task_title: taskTitle,
  });

  // Target team leader acknowledges and delegates
  const ackDelay = 1500 + Math.random() * 1000;
  setTimeout(() => {
    // Use the full delegation flow for the target department
    handleTaskDelegation(crossLeader, ceoMessage, "");
  }, ackDelay);
}

function findBestSubordinate(deptId: string, excludeId: string): AgentRow | null {
  // Find subordinates in department, prefer: idle > break, higher role first
  const agents = db.prepare(
    `SELECT * FROM agents WHERE department_id = ? AND id != ? AND role != 'team_leader' ORDER BY
       CASE status WHEN 'idle' THEN 0 WHEN 'break' THEN 1 WHEN 'working' THEN 2 ELSE 3 END,
       CASE role WHEN 'senior' THEN 0 WHEN 'junior' THEN 1 WHEN 'intern' THEN 2 ELSE 3 END`
  ).all(deptId, excludeId) as AgentRow[];
  return agents[0] ?? null;
}

function findTeamLeader(deptId: string | null): AgentRow | null {
  if (!deptId) return null;
  return (db.prepare(
    "SELECT * FROM agents WHERE department_id = ? AND role = 'team_leader' LIMIT 1"
  ).get(deptId) as AgentRow | undefined) ?? null;
}

function getDeptName(deptId: string): string {
  const d = db.prepare("SELECT name_ko FROM departments WHERE id = ?").get(deptId) as { name_ko: string } | undefined;
  return d?.name_ko ?? deptId;
}

// Role enforcement: restrict agents to their department's domain
function getDeptRoleConstraint(deptId: string, deptName: string): string {
  const constraints: Record<string, string> = {
    planning: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Planning). Focus ONLY on planning, strategy, market analysis, requirements, and documentation. Do NOT write production code, create design assets, or run tests. If coding/design is needed, describe requirements and specifications instead.`,
    dev: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Development). Focus ONLY on coding, debugging, code review, and technical implementation. Do NOT create design mockups, write business strategy documents, or perform QA testing.`,
    design: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Design). Focus ONLY on UI/UX design, visual assets, design specs, and prototyping. Do NOT write production backend code, run tests, or make infrastructure changes.`,
    qa: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (QA/QC). Focus ONLY on testing, quality assurance, test automation, and bug reporting. Do NOT write production code or create design assets.`,
    devsecops: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (DevSecOps). Focus ONLY on infrastructure, security audits, CI/CD pipelines, container orchestration, and deployment. Do NOT write business logic or create design assets.`,
    operations: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Operations). Focus ONLY on operations, automation, monitoring, maintenance, and process optimization. Do NOT write production code or create design assets.`,
  };
  return constraints[deptId] || `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName}. Focus on tasks within your department's expertise.`;
}

// ---------------------------------------------------------------------------
// Sequential cross-department cooperation: one department at a time
// ---------------------------------------------------------------------------
interface CrossDeptContext {
  teamLeader: AgentRow;
  taskTitle: string;
  ceoMessage: string;
  leaderDeptId: string;
  leaderDeptName: string;
  leaderName: string;
  lang: string;
  taskId: string;
}

function startCrossDeptCooperation(
  deptIds: string[],
  index: number,
  ctx: CrossDeptContext,
): void {
  if (index >= deptIds.length) return; // All departments processed

  const crossDeptId = deptIds[index];
  const crossLeader = findTeamLeader(crossDeptId);
  if (!crossLeader) {
    // Skip this dept, try next
    startCrossDeptCooperation(deptIds, index + 1, ctx);
    return;
  }

  const { teamLeader, taskTitle, ceoMessage, leaderDeptName, leaderName, lang, taskId } = ctx;
  const crossDeptName = getDeptName(crossDeptId);
  const crossLeaderName = lang === "ko" ? (crossLeader.name_ko || crossLeader.name) : crossLeader.name;

  // Notify remaining queue
  if (deptIds.length > 1) {
    const remaining = deptIds.length - index;
    notifyCeo(`협업 요청 진행 중: ${crossDeptName} (${index + 1}/${deptIds.length}, 남은 ${remaining}팀 순차 진행)`, taskId);
  }

  const coopReq = pickL(l(
    [`${crossLeaderName}님, 안녕하세요! 대표님 지시로 "${taskTitle}" 업무 진행 중인데, ${crossDeptName} 협조가 필요합니다. 도움 부탁드려요! 🤝`, `${crossLeaderName}님! "${taskTitle}" 건으로 ${crossDeptName} 지원이 필요합니다. 시간 되시면 협의 부탁드립니다.`],
    [`Hi ${crossLeaderName}! We're working on "${taskTitle}" per CEO's directive and need ${crossDeptName}'s support. Could you help? 🤝`, `${crossLeaderName}, we need ${crossDeptName}'s input on "${taskTitle}". Let's sync when you have a moment.`],
    [`${crossLeaderName}さん、CEO指示の"${taskTitle}"で${crossDeptName}の協力が必要です。お願いします！🤝`],
    [`${crossLeaderName}，CEO安排的"${taskTitle}"需要${crossDeptName}配合，麻烦协调一下！🤝`],
  ), lang);
  sendAgentMessage(teamLeader, coopReq, "chat", "agent", crossLeader.id, taskId);

  // Broadcast delivery animation event for UI
  broadcast("cross_dept_delivery", {
    from_agent_id: teamLeader.id,
    to_agent_id: crossLeader.id,
    task_title: taskTitle,
  });

  // Cross-department leader acknowledges AND creates a real task
  const crossAckDelay = 1500 + Math.random() * 1000;
  setTimeout(() => {
    const crossSub = findBestSubordinate(crossDeptId, crossLeader.id);
    const crossSubName = crossSub
      ? (lang === "ko" ? (crossSub.name_ko || crossSub.name) : crossSub.name)
      : null;

    const crossAckMsg = crossSub
      ? pickL(l(
        [`네, ${leaderName}님! 확인했습니다. ${crossSubName}에게 바로 배정하겠습니다 👍`, `알겠습니다! ${crossSubName}가 지원하도록 하겠습니다. 진행 상황 공유드릴게요.`],
        [`Sure, ${leaderName}! I'll assign ${crossSubName} to support right away 👍`, `Got it! ${crossSubName} will handle the ${crossDeptName} side. I'll keep you posted.`],
        [`了解しました、${leaderName}さん！${crossSubName}を割り当てます 👍`],
        [`好的，${leaderName}！安排${crossSubName}支援 👍`],
      ), lang)
      : pickL(l(
        [`네, ${leaderName}님! 확인했습니다. 제가 직접 처리하겠습니다 👍`],
        [`Sure, ${leaderName}! I'll handle it personally 👍`],
        [`了解しました！私が直接対応します 👍`],
        [`好的！我亲自来处理 👍`],
      ), lang);
    sendAgentMessage(crossLeader, crossAckMsg, "chat", "agent", null, taskId);

    // Create actual task in the cross-department
    const crossTaskId = randomUUID();
    const ct = nowMs();
    const crossTaskTitle = `[협업] ${taskTitle}`;
    const crossDetectedPath = detectProjectPath(ceoMessage);
    db.prepare(`
      INSERT INTO tasks (id, title, description, department_id, status, priority, task_type, project_path, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'planned', 1, 'general', ?, ?, ?)
    `).run(crossTaskId, crossTaskTitle, `[Cross-dept from ${leaderDeptName}] ${ceoMessage}`, crossDeptId, crossDetectedPath, ct, ct);
    appendTaskLog(crossTaskId, "system", `Cross-dept request from ${leaderName} (${leaderDeptName})`);
    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(crossTaskId));

    // Delegate to cross-dept subordinate and spawn CLI
    const execAgent = crossSub || crossLeader;
    const execName = lang === "ko" ? (execAgent.name_ko || execAgent.name) : execAgent.name;
    const ct2 = nowMs();
    db.prepare(
      "UPDATE tasks SET assigned_agent_id = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
    ).run(execAgent.id, ct2, ct2, crossTaskId);
    db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(crossTaskId, execAgent.id);
    appendTaskLog(crossTaskId, "system", `${crossLeaderName} → ${execName}`);

    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(crossTaskId));
    broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(execAgent.id));

    // Register callback to start next department when this one finishes
    if (index + 1 < deptIds.length) {
      crossDeptNextCallbacks.set(crossTaskId, () => {
        const nextDelay = 2000 + Math.random() * 1000;
        setTimeout(() => {
          startCrossDeptCooperation(deptIds, index + 1, ctx);
        }, nextDelay);
      });
    }

    // Actually spawn the CLI agent
    const execProvider = execAgent.cli_provider || "claude";
    if (["claude", "codex", "gemini", "opencode"].includes(execProvider)) {
      const crossTaskData = db.prepare("SELECT * FROM tasks WHERE id = ?").get(crossTaskId) as {
        title: string; description: string | null; project_path: string | null;
      } | undefined;
      if (crossTaskData) {
        const projPath = resolveProjectPath(crossTaskData);
        const logFilePath = path.join(logsDir, `${crossTaskId}.log`);
        const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[execAgent.role] || execAgent.role;
        const deptConstraint = getDeptRoleConstraint(crossDeptId, crossDeptName);
        const crossConversationCtx = getRecentConversationContext(execAgent.id);
        const spawnPrompt = [
          `[Task] ${crossTaskData.title}`,
          crossTaskData.description ? `\n${crossTaskData.description}` : "",
          crossConversationCtx,
          `\n---`,
          `Agent: ${execAgent.name} (${roleLabel}, ${crossDeptName})`,
          execAgent.personality ? `Personality: ${execAgent.personality}` : "",
          deptConstraint,
          `Please complete the task above thoroughly. Use the conversation context above if relevant.`,
        ].filter(Boolean).join("\n");

        appendTaskLog(crossTaskId, "system", `RUN start (agent=${execAgent.name}, provider=${execProvider})`);
        const child = spawnCliAgent(crossTaskId, execProvider, spawnPrompt, projPath, logFilePath);
        child.on("close", (code) => {
          handleTaskRunComplete(crossTaskId, code ?? 1);
        });

        notifyCeo(`${crossDeptName} ${execName}가 '${taskTitle}' 협업 작업을 시작했습니다.`, crossTaskId);
        startProgressTimer(crossTaskId, crossTaskData.title, crossDeptId);
      }
    }
  }, crossAckDelay);
}

/**
 * Detect project path from CEO message.
 * Recognizes:
 * 1. Absolute paths: /Users/classys/Projects/foo, ~/Projects/bar
 * 2. Project names: "climpire 프로젝트", "claw-kanban에서"
 * 3. Known project directories under ~/Projects
 */
function detectProjectPath(message: string): string | null {
  const homeDir = os.homedir();
  const projectsDir = path.join(homeDir, "Projects");
  const projectsDirLower = path.join(homeDir, "projects");

  // 1. Explicit absolute path in message
  const absMatch = message.match(/(?:^|\s)(\/[\w./-]+)/);
  if (absMatch) {
    const p = absMatch[1];
    // Check if it's a real directory
    try {
      if (fs.statSync(p).isDirectory()) return p;
    } catch {}
    // Check parent directory
    const parent = path.dirname(p);
    try {
      if (fs.statSync(parent).isDirectory()) return parent;
    } catch {}
  }

  // 2. ~ path
  const tildeMatch = message.match(/~\/([\w./-]+)/);
  if (tildeMatch) {
    const expanded = path.join(homeDir, tildeMatch[1]);
    try {
      if (fs.statSync(expanded).isDirectory()) return expanded;
    } catch {}
  }

  // 3. Scan known project directories and match by name
  let knownProjects: string[] = [];
  for (const pDir of [projectsDir, projectsDirLower]) {
    try {
      const entries = fs.readdirSync(pDir, { withFileTypes: true });
      knownProjects = knownProjects.concat(
        entries.filter(e => e.isDirectory() && !e.name.startsWith('.')).map(e => e.name)
      );
    } catch {}
  }

  // Match project names in the message (case-insensitive)
  const msgLower = message.toLowerCase();
  for (const proj of knownProjects) {
    if (msgLower.includes(proj.toLowerCase())) {
      // Return the actual path
      const fullPath = path.join(projectsDir, proj);
      try {
        if (fs.statSync(fullPath).isDirectory()) return fullPath;
      } catch {}
      const fullPathLower = path.join(projectsDirLower, proj);
      try {
        if (fs.statSync(fullPathLower).isDirectory()) return fullPathLower;
      } catch {}
    }
  }

  return null;
}

/** Resolve project path: task.project_path → detect from message → cwd */
function resolveProjectPath(task: { project_path?: string | null; description?: string | null; title?: string }): string {
  if (task.project_path) return task.project_path;
  // Try to detect from description or title
  const detected = detectProjectPath(task.description || "") || detectProjectPath(task.title || "");
  return detected || process.cwd();
}

function handleTaskDelegation(
  teamLeader: AgentRow,
  ceoMessage: string,
  ceoMsgId: string,
): void {
  const lang = detectLang(ceoMessage);
  const leaderName = lang === "ko" ? (teamLeader.name_ko || teamLeader.name) : teamLeader.name;
  const leaderDeptId = teamLeader.department_id!;
  const leaderDeptName = getDeptName(leaderDeptId);

  // --- Step 1: Team leader acknowledges (1~2 sec) ---
  const ackDelay = 1000 + Math.random() * 1000;
  setTimeout(() => {
    const subordinate = findBestSubordinate(leaderDeptId, teamLeader.id);

    const taskId = randomUUID();
    const t = nowMs();
    const taskTitle = ceoMessage.length > 60 ? ceoMessage.slice(0, 57) + "..." : ceoMessage;
    const detectedPath = detectProjectPath(ceoMessage);
    db.prepare(`
      INSERT INTO tasks (id, title, description, department_id, status, priority, task_type, project_path, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'planned', 1, 'general', ?, ?, ?)
    `).run(taskId, taskTitle, `[CEO] ${ceoMessage}`, leaderDeptId, detectedPath, t, t);
    appendTaskLog(taskId, "system", `CEO → ${leaderName}: ${ceoMessage}`);
    if (detectedPath) {
      appendTaskLog(taskId, "system", `Project path detected: ${detectedPath}`);
    }

    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));

    const mentionedDepts = detectTargetDepartments(ceoMessage).filter((d) => d !== leaderDeptId);

    if (subordinate) {
      const subName = lang === "ko" ? (subordinate.name_ko || subordinate.name) : subordinate.name;
      const subRole = getRoleLabel(subordinate.role, lang);

      let ackMsg: string;
      if (mentionedDepts.length > 0) {
        const crossDeptNames = mentionedDepts.map(getDeptName).join(", ");
        ackMsg = pickL(l(
          [`네, 대표님! 확인했습니다. ${subRole} ${subName}에게 할당하고, ${crossDeptNames}에도 협조 요청하겠습니다! 📋`, `알겠습니다! ${subName}가 메인으로 진행하고, ${crossDeptNames}과 협업 조율하겠습니다 🤝`],
          [`Got it! I'll assign this to ${subRole} ${subName} and coordinate with ${crossDeptNames} 📋`, `Understood! ${subName} will take the lead, and I'll loop in ${crossDeptNames} 🤝`],
          [`了解しました！${subRole} ${subName}に割り当て、${crossDeptNames}にも協力依頼します！📋`],
          [`收到！交给${subRole} ${subName}，同时协调${crossDeptNames} 📋`],
        ), lang);
      } else {
        ackMsg = pickL(l(
          [`네, 대표님! 확인했습니다. ${subRole} ${subName}에게 바로 할당하겠습니다! 📋`, `알겠습니다! 우리 팀 ${subName}가 적임자입니다. 바로 지시하겠습니다 🚀`, `확인했습니다, 대표님! ${subName}에게 전달하고 진행 관리하겠습니다.`],
          [`Got it! I'll assign this to ${subRole} ${subName} right away! 📋`, `Understood! ${subName} is the perfect fit. Delegating now 🚀`, `Confirmed! I'll hand this off to ${subName} and manage progress.`],
          [`了解しました！${subRole} ${subName}にすぐ割り当てます！📋`, `承知しました！${subName}に指示します 🚀`],
          [`收到！马上分配给${subRole} ${subName}！📋`, `明白！${subName}最合适，立即安排 🚀`],
        ), lang);
      }
      sendAgentMessage(teamLeader, ackMsg, "chat", "agent", null, taskId);

      // --- Step 2: Delegate to subordinate (2~3 sec) ---
      const delegateDelay = 2000 + Math.random() * 1000;
      setTimeout(() => {
        const t2 = nowMs();
        db.prepare(
          "UPDATE tasks SET assigned_agent_id = ?, status = 'planned', updated_at = ? WHERE id = ?"
        ).run(subordinate.id, t2, taskId);
        db.prepare("UPDATE agents SET current_task_id = ? WHERE id = ?").run(taskId, subordinate.id);
        appendTaskLog(taskId, "system", `${leaderName} → ${subName}`);

        broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
        broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(subordinate.id));

        const delegateMsg = pickL(l(
          [`${subName}, 대표님 지시사항이야. "${ceoMessage}" — 확인하고 진행해줘!`, `${subName}! 긴급 업무야. "${ceoMessage}" — 우선순위 높게 처리 부탁해.`, `${subName}, 새 업무 할당이야: "${ceoMessage}" — 진행 상황 수시로 공유해줘 👍`],
          [`${subName}, directive from the CEO: "${ceoMessage}" — please handle this!`, `${subName}! Priority task: "${ceoMessage}" — needs immediate attention.`, `${subName}, new assignment: "${ceoMessage}" — keep me posted on progress 👍`],
          [`${subName}、CEOからの指示だよ。"${ceoMessage}" — 確認して進めて！`, `${subName}！優先タスク: "${ceoMessage}" — よろしく頼む 👍`],
          [`${subName}，CEO的指示："${ceoMessage}" — 请跟进处理！`, `${subName}！优先任务："${ceoMessage}" — 随时更新进度 👍`],
        ), lang);
        sendAgentMessage(teamLeader, delegateMsg, "task_assign", "agent", subordinate.id, taskId);

        // --- Step 3: Subordinate acknowledges (1~2 sec) ---
        const subAckDelay = 1000 + Math.random() * 1000;
        setTimeout(() => {
          const leaderRole = getRoleLabel(teamLeader.role, lang);
          const subAckMsg = pickL(l(
            [`네, ${leaderRole} ${leaderName}님! 확인했습니다. 바로 착수하겠습니다! 💪`, `알겠습니다! 바로 시작하겠습니다. 진행 상황 공유 드리겠습니다.`, `확인했습니다, ${leaderName}님! 최선을 다해 처리하겠습니다 🔥`],
            [`Yes, ${leaderName}! Confirmed. Starting right away! 💪`, `Got it! On it now. I'll keep you updated on progress.`, `Confirmed, ${leaderName}! I'll give it my best 🔥`],
            [`はい、${leaderName}さん！了解しました。すぐ取りかかります！💪`, `承知しました！進捗共有します 🔥`],
            [`好的，${leaderName}！收到，马上开始！💪`, `明白了！会及时汇报进度 🔥`],
          ), lang);
          sendAgentMessage(subordinate, subAckMsg, "chat", "agent", null, taskId);

          const t3 = nowMs();
          db.prepare(
            "UPDATE tasks SET status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
          ).run(t3, t3, taskId);
          db.prepare(
            "UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?"
          ).run(taskId, subordinate.id);
          appendTaskLog(taskId, "system", `${subName} started`);

          broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
          broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(subordinate.id));

          // Actually spawn the CLI agent to do the work
          const subProvider = subordinate.cli_provider || "claude";
          if (["claude", "codex", "gemini", "opencode"].includes(subProvider)) {
            const taskData = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
              title: string; description: string | null; project_path: string | null;
            } | undefined;
            if (taskData) {
              const projPath = resolveProjectPath(taskData);
              const logFilePath = path.join(logsDir, `${taskId}.log`);
              const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[subordinate.role] || subordinate.role;
              const deptConstraint = getDeptRoleConstraint(leaderDeptId, leaderDeptName);
              const conversationCtx = getRecentConversationContext(subordinate.id);
              const spawnPrompt = [
                `[Task] ${taskData.title}`,
                taskData.description ? `\n${taskData.description}` : "",
                conversationCtx,
                `\n---`,
                `Agent: ${subordinate.name} (${roleLabel}, ${leaderDeptName})`,
                subordinate.personality ? `Personality: ${subordinate.personality}` : "",
                deptConstraint,
                `Please complete the task above thoroughly. Use the conversation context above if relevant.`,
              ].filter(Boolean).join("\n");

              appendTaskLog(taskId, "system", `RUN start (agent=${subordinate.name}, provider=${subProvider})`);
              const child = spawnCliAgent(taskId, subProvider, spawnPrompt, projPath, logFilePath);
              child.on("close", (code) => {
                handleTaskRunComplete(taskId, code ?? 1);
              });

              notifyCeo(`${subName}가 '${taskData.title}' 작업을 시작했습니다.`, taskId);
              startProgressTimer(taskId, taskData.title, leaderDeptId);
            }
          }
        }, subAckDelay);

        // --- Step 4: Cross-department cooperation (SEQUENTIAL — one dept at a time) ---
        if (mentionedDepts.length > 0) {
          const crossDelay = 3000 + Math.random() * 1000;
          setTimeout(() => {
            // Start only the first department; subsequent ones are chained via crossDeptNextCallbacks
            startCrossDeptCooperation(mentionedDepts, 0, {
              teamLeader, taskTitle, ceoMessage, leaderDeptId, leaderDeptName, leaderName, lang, taskId,
            });
          }, crossDelay);
        }
      }, delegateDelay);
    } else {
      // No subordinate — team leader handles it themselves
      const selfMsg = pickL(l(
        [`네, 대표님! 확인했습니다. 현재 팀원들이 모두 업무 중이라 제가 직접 처리하겠습니다! 💪`, `알겠습니다! 팀 내 여유 인력이 없어서 제가 직접 진행하겠습니다.`],
        [`Got it! All team members are busy, so I'll handle this personally! 💪`, `Understood! No one's available, so I'll take this on myself.`],
        [`了解しました！チームメンバーが全員稼働中なので、私が直接対応します！💪`],
        [`收到！团队都在忙，我亲自来处理！💪`],
      ), lang);
      sendAgentMessage(teamLeader, selfMsg, "chat", "agent", null, taskId);

      const t2 = nowMs();
      db.prepare(
        "UPDATE tasks SET assigned_agent_id = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
      ).run(teamLeader.id, t2, t2, taskId);
      db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(taskId, teamLeader.id);
      appendTaskLog(taskId, "system", `${leaderName} self-assigned`);

      broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
      broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(teamLeader.id));
    }
  }, ackDelay);
}

// ---- Non-team-leader agents: simple chat reply ----

function scheduleAgentReply(agentId: string, ceoMessage: string, messageType: string): void {
  const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
  if (!agent) return;

  // If it's a task_assign to a team leader, use delegation flow
  if (messageType === "task_assign" && agent.role === "team_leader" && agent.department_id) {
    handleTaskDelegation(agent, ceoMessage, "");
    return;
  }

  // Regular chat reply
  const delay = 1000 + Math.random() * 2000;
  setTimeout(() => {
    const reply = generateChatReply(agent, ceoMessage);
    sendAgentMessage(agent, reply);
  }, delay);
}

// ---------------------------------------------------------------------------
// Messages / Chat
// ---------------------------------------------------------------------------
app.get("/api/messages", (req, res) => {
  const receiverType = firstQueryValue(req.query.receiver_type);
  const receiverId = firstQueryValue(req.query.receiver_id);
  const limitRaw = firstQueryValue(req.query.limit);
  const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 500);

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (receiverType && receiverId) {
    // Conversation with a specific agent: show messages TO and FROM that agent
    conditions.push(
      "((receiver_type = ? AND receiver_id = ?) OR (sender_type = 'agent' AND sender_id = ?) OR receiver_type = 'all')"
    );
    params.push(receiverType, receiverId, receiverId);
  } else if (receiverType) {
    conditions.push("receiver_type = ?");
    params.push(receiverType);
  } else if (receiverId) {
    conditions.push("(receiver_id = ? OR receiver_type = 'all')");
    params.push(receiverId);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  params.push(limit);

  const messages = db.prepare(`
    SELECT m.*,
      a.name AS sender_name,
      a.avatar_emoji AS sender_avatar
    FROM messages m
    LEFT JOIN agents a ON m.sender_type = 'agent' AND m.sender_id = a.id
    ${where}
    ORDER BY m.created_at DESC
    LIMIT ?
  `).all(...params);

  res.json({ messages: messages.reverse() }); // return in chronological order
});

app.post("/api/messages", (req, res) => {
  const body = req.body ?? {};
  const id = randomUUID();
  const t = nowMs();

  const content = body.content;
  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "content_required" });
  }

  const senderType = body.sender_type || "ceo";
  const senderId = body.sender_id ?? null;
  const receiverType = body.receiver_type || "all";
  const receiverId = body.receiver_id ?? null;
  const messageType = body.message_type || "chat";
  const taskId = body.task_id ?? null;

  db.prepare(`
    INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, senderType, senderId, receiverType, receiverId, content, messageType, taskId, t);

  const msg = {
    id,
    sender_type: senderType,
    sender_id: senderId,
    receiver_type: receiverType,
    receiver_id: receiverId,
    content,
    message_type: messageType,
    task_id: taskId,
    created_at: t,
  };

  broadcast("new_message", msg);

  // Schedule agent auto-reply when CEO messages an agent
  if (senderType === "ceo" && receiverType === "agent" && receiverId) {
    scheduleAgentReply(receiverId, content, messageType);

    // Check for @mentions to other departments/agents
    const mentions = detectMentions(content);
    if (mentions.deptIds.length > 0 || mentions.agentIds.length > 0) {
      const senderAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(receiverId) as AgentRow | undefined;
      if (senderAgent) {
        const lang = detectLang(content);
        const mentionDelay = 4000 + Math.random() * 2000; // After the main delegation starts
        setTimeout(() => {
          // Handle department mentions
          for (const deptId of mentions.deptIds) {
            if (deptId === senderAgent.department_id) continue; // Skip own department
            handleMentionDelegation(senderAgent, deptId, content, lang);
          }
          // Handle agent mentions — find their department and delegate there
          for (const agentId of mentions.agentIds) {
            const mentioned = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
            if (mentioned && mentioned.department_id && mentioned.department_id !== senderAgent.department_id) {
              if (!mentions.deptIds.includes(mentioned.department_id)) {
                handleMentionDelegation(senderAgent, mentioned.department_id, content, lang);
              }
            }
          }
        }, mentionDelay);
      }
    }
  }

  res.json({ ok: true, message: msg });
});

app.post("/api/announcements", (req, res) => {
  const body = req.body ?? {};
  const content = body.content;
  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "content_required" });
  }

  const id = randomUUID();
  const t = nowMs();

  db.prepare(`
    INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, created_at)
    VALUES (?, 'ceo', NULL, 'all', NULL, ?, 'announcement', ?)
  `).run(id, content, t);

  const msg = {
    id,
    sender_type: "ceo",
    sender_id: null,
    receiver_type: "all",
    receiver_id: null,
    content,
    message_type: "announcement",
    created_at: t,
  };

  broadcast("announcement", msg);

  // Team leaders respond to announcements with staggered delays
  scheduleAnnouncementReplies(content);

  // Check for @mentions in announcements — trigger delegation
  const mentions = detectMentions(content);
  if (mentions.deptIds.length > 0 || mentions.agentIds.length > 0) {
    const lang = detectLang(content);
    const mentionDelay = 5000 + Math.random() * 2000;
    setTimeout(() => {
      const processedDepts = new Set<string>();

      for (const deptId of mentions.deptIds) {
        if (processedDepts.has(deptId)) continue;
        processedDepts.add(deptId);
        const leader = findTeamLeader(deptId);
        if (leader) {
          handleTaskDelegation(leader, content, "");
        }
      }

      for (const agentId of mentions.agentIds) {
        const mentioned = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
        if (mentioned?.department_id && !processedDepts.has(mentioned.department_id)) {
          processedDepts.add(mentioned.department_id);
          const leader = findTeamLeader(mentioned.department_id);
          if (leader) {
            handleTaskDelegation(leader, content, "");
          }
        }
      }
    }, mentionDelay);
  }

  res.json({ ok: true, message: msg });
});

// Delete conversation messages
app.delete("/api/messages", (req, res) => {
  const agentId = firstQueryValue(req.query.agent_id);
  const scope = firstQueryValue(req.query.scope) || "conversation"; // "conversation" or "all"

  if (scope === "all") {
    // Delete all messages (announcements + conversations)
    const result = db.prepare("DELETE FROM messages").run();
    broadcast("messages_cleared", { scope: "all" });
    return res.json({ ok: true, deleted: result.changes });
  }

  if (agentId) {
    // Delete messages for a specific agent conversation + announcements shown in that chat
    const result = db.prepare(
      `DELETE FROM messages WHERE
        (sender_type = 'ceo' AND receiver_type = 'agent' AND receiver_id = ?)
        OR (sender_type = 'agent' AND sender_id = ?)
        OR receiver_type = 'all'
        OR message_type = 'announcement'`
    ).run(agentId, agentId);
    broadcast("messages_cleared", { scope: "agent", agent_id: agentId });
    return res.json({ ok: true, deleted: result.changes });
  }

  // Delete only announcements/broadcasts
  const result = db.prepare(
    "DELETE FROM messages WHERE receiver_type = 'all' OR message_type = 'announcement'"
  ).run();
  broadcast("messages_cleared", { scope: "announcements" });
  res.json({ ok: true, deleted: result.changes });
});

// ---------------------------------------------------------------------------
// CLI Status
// ---------------------------------------------------------------------------
app.get("/api/cli-status", async (_req, res) => {
  const refresh = _req.query.refresh === "1";
  const now = Date.now();

  if (!refresh && cachedCliStatus && now - cachedCliStatus.loadedAt < CLI_STATUS_TTL) {
    return res.json({ providers: cachedCliStatus.data });
  }

  try {
    const data = await detectAllCli();
    cachedCliStatus = { data, loadedAt: Date.now() };
    res.json({ providers: data });
  } catch (err) {
    res.status(500).json({ error: "cli_detection_failed", message: String(err) });
  }
});

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
app.get("/api/settings", (_req, res) => {
  const rows = db.prepare("SELECT key, value FROM settings").all() as { key: string; value: string }[];
  const settings: Record<string, unknown> = {};
  for (const row of rows) {
    try {
      settings[row.key] = JSON.parse(row.value);
    } catch {
      settings[row.key] = row.value;
    }
  }
  res.json({ settings });
});

app.put("/api/settings", (req, res) => {
  const body = req.body ?? {};

  const upsert = db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  );

  for (const [key, value] of Object.entries(body)) {
    upsert.run(key, typeof value === "string" ? value : JSON.stringify(value));
  }

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Stats / Dashboard
// ---------------------------------------------------------------------------
app.get("/api/stats", (_req, res) => {
  const totalTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks").get() as { cnt: number }).cnt;
  const doneTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'done'").get() as { cnt: number }).cnt;
  const inProgressTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'in_progress'").get() as { cnt: number }).cnt;
  const inboxTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'inbox'").get() as { cnt: number }).cnt;
  const plannedTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'planned'").get() as { cnt: number }).cnt;
  const reviewTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'review'").get() as { cnt: number }).cnt;
  const cancelledTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'cancelled'").get() as { cnt: number }).cnt;

  const totalAgents = (db.prepare("SELECT COUNT(*) as cnt FROM agents").get() as { cnt: number }).cnt;
  const workingAgents = (db.prepare("SELECT COUNT(*) as cnt FROM agents WHERE status = 'working'").get() as { cnt: number }).cnt;
  const idleAgents = (db.prepare("SELECT COUNT(*) as cnt FROM agents WHERE status = 'idle'").get() as { cnt: number }).cnt;

  const completionRate = totalTasks > 0 ? Math.round((doneTasks / totalTasks) * 100) : 0;

  // Top agents by XP
  const topAgents = db.prepare(
    "SELECT id, name, avatar_emoji, stats_tasks_done, stats_xp FROM agents ORDER BY stats_xp DESC LIMIT 5"
  ).all();

  // Tasks per department
  const tasksByDept = db.prepare(`
    SELECT d.id, d.name, d.icon, d.color,
      COUNT(t.id) AS total_tasks,
      SUM(CASE WHEN t.status = 'done' THEN 1 ELSE 0 END) AS done_tasks
    FROM departments d
    LEFT JOIN tasks t ON t.department_id = d.id
    GROUP BY d.id
    ORDER BY d.name
  `).all();

  // Recent activity (last 20 task logs)
  const recentActivity = db.prepare(`
    SELECT tl.*, t.title AS task_title
    FROM task_logs tl
    LEFT JOIN tasks t ON tl.task_id = t.id
    ORDER BY tl.created_at DESC
    LIMIT 20
  `).all();

  res.json({
    stats: {
      tasks: {
        total: totalTasks,
        done: doneTasks,
        in_progress: inProgressTasks,
        inbox: inboxTasks,
        planned: plannedTasks,
        review: reviewTasks,
        cancelled: cancelledTasks,
        completion_rate: completionRate,
      },
      agents: {
        total: totalAgents,
        working: workingAgents,
        idle: idleAgents,
      },
      top_agents: topAgents,
      tasks_by_department: tasksByDept,
      recent_activity: recentActivity,
    },
  });
});

// ---------------------------------------------------------------------------
// prettyStreamJson: parse stream-JSON from Claude/Codex/Gemini into readable text
// (ported from claw-kanban)
// ---------------------------------------------------------------------------
function prettyStreamJson(raw: string): string {
  const chunks: string[] = [];
  const meta: string[] = [];

  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (!t.startsWith("{")) continue;

    try {
      const j: any = JSON.parse(t);

      // Claude: system init
      if (j.type === "system" && j.subtype === "init") {
        meta.push(`[init] cwd=${j.cwd} model=${j.model}`);
        if (Array.isArray(j.mcp_servers)) {
          const failed = j.mcp_servers.filter((s: any) => s.status && s.status !== "ok");
          if (failed.length) meta.push(`[mcp] ${failed.map((s: any) => `${s.name}:${s.status}`).join(", ")}`);
        }
        continue;
      }

      // Gemini: init
      if (j.type === "init" && j.session_id) {
        meta.push(`[init] session=${j.session_id} model=${j.model}`);
        continue;
      }

      // Claude: stream_event
      if (j.type === "stream_event") {
        const ev = j.event;
        if (ev?.type === "content_block_delta" && ev?.delta?.type === "text_delta") {
          chunks.push(ev.delta.text);
          continue;
        }
        if (ev?.type === "content_block_start" && ev?.content_block?.type === "text" && ev?.content_block?.text) {
          chunks.push(ev.content_block.text);
          continue;
        }
        continue;
      }

      // Claude: assistant message (from --print mode)
      if (j.type === "assistant" && j.message?.content) {
        for (const block of j.message.content) {
          if (block.type === "text" && block.text) {
            chunks.push(block.text);
          }
        }
        continue;
      }

      // Claude: result (final output from --print mode)
      if (j.type === "result" && j.result) {
        chunks.push(j.result);
        continue;
      }

      // Gemini: message with content
      if (j.type === "message" && j.role === "assistant" && j.content) {
        chunks.push(j.content);
        continue;
      }

      // Gemini: tool_use
      if (j.type === "tool_use" && j.tool_name) {
        const params = j.parameters?.file_path || j.parameters?.command || "";
        chunks.push(`\n[tool: ${j.tool_name}] ${params}\n`);
        continue;
      }

      // Gemini: tool_result
      if (j.type === "tool_result" && j.status) {
        if (j.status !== "success") {
          chunks.push(`[result: ${j.status}]\n`);
        }
        continue;
      }

      // Codex: thread.started
      if (j.type === "thread.started" && j.thread_id) {
        meta.push(`[thread] ${j.thread_id}`);
        continue;
      }

      // Codex: item.completed (reasoning or agent_message)
      if (j.type === "item.completed" && j.item) {
        const item = j.item;
        if (item.type === "agent_message" && item.text) {
          chunks.push(item.text);
        } else if (item.type === "reasoning" && item.text) {
          chunks.push(`\n[reasoning] ${item.text}\n`);
        } else if (item.type === "tool_call" && item.name) {
          const args = item.arguments ? JSON.stringify(item.arguments).slice(0, 100) : "";
          chunks.push(`\n[tool: ${item.name}] ${args}\n`);
        } else if (item.type === "tool_output" && item.output) {
          const out = String(item.output);
          if (out.includes("error") || out.length < 200) {
            chunks.push(`[output] ${out.slice(0, 200)}\n`);
          }
        }
        continue;
      }

      // Codex: turn.completed (usage stats)
      if (j.type === "turn.completed" && j.usage) {
        const u = j.usage;
        meta.push(`[usage] in=${u.input_tokens} out=${u.output_tokens} cached=${u.cached_input_tokens || 0}`);
        continue;
      }
    } catch {
      // ignore
    }
  }

  // Fallback: if no JSON was parsed, return raw text (e.g. plain-text logs)
  if (chunks.length === 0 && meta.length === 0) {
    return raw.trim();
  }

  const stitched = chunks.join("");
  const PARA = "\u0000";
  const withPara = stitched.replace(/\n{2,}/g, PARA);
  const singleLine = withPara.replace(/\n/g, " ");
  const normalized = singleLine
    .replace(/\s+/g, " ")
    .replace(new RegExp(PARA, "g"), "\n\n")
    .trim();

  const head = meta.length ? meta.join("\n") + "\n\n" : "";
  return head + normalized;
}

// ---------------------------------------------------------------------------
// Task terminal log viewer (ported from claw-kanban)
// ---------------------------------------------------------------------------
app.get("/api/tasks/:id/terminal", (req, res) => {
  const id = String(req.params.id);
  const lines = Math.min(Math.max(Number(req.query.lines ?? 200), 20), 4000);
  const pretty = String(req.query.pretty ?? "0") === "1";
  const filePath = path.join(logsDir, `${id}.log`);

  if (!fs.existsSync(filePath)) {
    return res.json({ ok: true, exists: false, path: filePath, text: "" });
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const parts = raw.split(/\r?\n/);
  const tail = parts.slice(Math.max(0, parts.length - lines)).join("\n");
  let text = tail;
  if (pretty) {
    const parsed = prettyStreamJson(tail);
    // If pretty parsing produced empty/whitespace but raw has content, fall back to raw
    text = parsed.trim() ? parsed : tail;
  }

  // Also return task_logs (system events) for interleaved display
  const taskLogs = db.prepare(
    "SELECT id, kind, message, created_at FROM task_logs WHERE task_id = ? ORDER BY created_at ASC"
  ).all(id) as Array<{ id: number; kind: string; message: string; created_at: number }>;

  res.json({ ok: true, exists: true, path: filePath, text, task_logs: taskLogs });
});

// ---------------------------------------------------------------------------
// OAuth web-auth helper functions
// ---------------------------------------------------------------------------
function consumeOAuthState(stateId: string, provider: string): { verifier_enc: string; redirect_to: string | null } | null {
  const row = db.prepare(
    "SELECT provider, verifier_enc, redirect_to, created_at FROM oauth_states WHERE id = ?"
  ).get(stateId) as { provider: string; verifier_enc: string; redirect_to: string | null; created_at: number } | undefined;
  if (!row) return null;
  // Always delete (one-time use)
  db.prepare("DELETE FROM oauth_states WHERE id = ?").run(stateId);
  // Check TTL
  if (Date.now() - row.created_at > OAUTH_STATE_TTL_MS) return null;
  // Check provider match
  if (row.provider !== provider) return null;
  return { verifier_enc: row.verifier_enc, redirect_to: row.redirect_to };
}

function upsertOAuthCredential(input: {
  provider: string;
  source: string;
  email: string | null;
  scope: string | null;
  access_token: string;
  refresh_token: string | null;
  expires_at: number | null;
}): void {
  const now = nowMs();
  const accessEnc = encryptSecret(input.access_token);
  const refreshEnc = input.refresh_token ? encryptSecret(input.refresh_token) : null;
  const encData = encryptSecret(JSON.stringify({ access_token: input.access_token }));

  db.prepare(`
    INSERT INTO oauth_credentials (provider, source, encrypted_data, email, scope, expires_at, created_at, updated_at, access_token_enc, refresh_token_enc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(provider) DO UPDATE SET
      source = excluded.source,
      encrypted_data = excluded.encrypted_data,
      email = excluded.email,
      scope = excluded.scope,
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at,
      access_token_enc = excluded.access_token_enc,
      refresh_token_enc = excluded.refresh_token_enc
  `).run(
    input.provider, input.source, encData, input.email, input.scope,
    input.expires_at, now, now, accessEnc, refreshEnc
  );
}

function startGitHubOAuth(redirectTo: string | undefined, callbackPath: string): string {
  if (!OAUTH_GITHUB_CLIENT_ID) throw new Error("OAUTH_GITHUB_CLIENT_ID not configured");
  const stateId = randomUUID();
  const safeRedirect = sanitizeOAuthRedirect(redirectTo);
  // Store state (verifier not used for GitHub, but store placeholder)
  db.prepare(
    "INSERT INTO oauth_states (id, provider, created_at, verifier_enc, redirect_to) VALUES (?, ?, ?, ?, ?)"
  ).run(stateId, "github", Date.now(), "", safeRedirect);

  const params = new URLSearchParams({
    client_id: OAUTH_GITHUB_CLIENT_ID,
    redirect_uri: `${OAUTH_BASE_URL}${callbackPath}`,
    scope: "read:user user:email",
    state: stateId,
  });
  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

function startGoogleOAuth(redirectTo: string | undefined, callbackPath: string): string {
  if (!OAUTH_GOOGLE_CLIENT_ID) throw new Error("OAUTH_GOOGLE_CLIENT_ID not configured");
  const stateId = randomUUID();
  const verifier = pkceVerifier();
  const safeRedirect = sanitizeOAuthRedirect(redirectTo);
  // Store state with encrypted PKCE verifier
  const verifierEnc = encryptSecret(verifier);
  db.prepare(
    "INSERT INTO oauth_states (id, provider, created_at, verifier_enc, redirect_to) VALUES (?, ?, ?, ?, ?)"
  ).run(stateId, "google", Date.now(), verifierEnc, safeRedirect);

  // pkceChallengeS256 is async, but we compute synchronously since createHash is sync
  const challenge = b64url(createHash("sha256").update(verifier, "ascii").digest());

  const params = new URLSearchParams({
    client_id: OAUTH_GOOGLE_CLIENT_ID,
    redirect_uri: `${OAUTH_BASE_URL}${callbackPath}`,
    response_type: "code",
    scope: "openid email profile",
    state: stateId,
    code_challenge: challenge,
    code_challenge_method: "S256",
    access_type: "offline",
    prompt: "consent",
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

async function handleGitHubCallback(code: string, stateId: string, callbackPath: string): Promise<{ redirectTo: string }> {
  const stateRow = consumeOAuthState(stateId, "github");
  if (!stateRow) throw new Error("Invalid or expired state");

  // Exchange code for token
  const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: OAUTH_GITHUB_CLIENT_ID,
      client_secret: OAUTH_GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${OAUTH_BASE_URL}${callbackPath}`,
    }),
    signal: AbortSignal.timeout(10000),
  });
  const tokenData = await tokenResp.json() as { access_token?: string; error?: string; scope?: string };
  if (!tokenData.access_token) throw new Error(tokenData.error || "No access token received");

  // Fetch user info
  const userResp = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: "application/json" },
    signal: AbortSignal.timeout(8000),
  });
  const userData = await userResp.json() as { login?: string; email?: string };

  // Fetch primary email if not public
  let email = userData.email || userData.login || null;
  if (!userData.email) {
    try {
      const emailResp = await fetch("https://api.github.com/user/emails", {
        headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: "application/json" },
        signal: AbortSignal.timeout(5000),
      });
      const emails = await emailResp.json() as Array<{ email: string; primary: boolean }>;
      const primary = emails.find((e) => e.primary);
      if (primary) email = primary.email;
    } catch { /* use login as fallback */ }
  }

  upsertOAuthCredential({
    provider: "github",
    source: "web-oauth",
    email,
    scope: tokenData.scope || "read:user,user:email",
    access_token: tokenData.access_token,
    refresh_token: null,
    expires_at: null,
  });

  const redirect = stateRow.redirect_to || "/";
  return { redirectTo: appendOAuthQuery(redirect.startsWith("/") ? `${OAUTH_BASE_URL}${redirect}` : redirect, "oauth", "github") };
}

async function handleGoogleCallback(code: string, stateId: string, callbackPath: string): Promise<{ redirectTo: string }> {
  const stateRow = consumeOAuthState(stateId, "google");
  if (!stateRow) throw new Error("Invalid or expired state");

  // Decrypt PKCE verifier
  const verifier = decryptSecret(stateRow.verifier_enc);

  // Exchange code for token
  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: OAUTH_GOOGLE_CLIENT_ID,
      client_secret: OAUTH_GOOGLE_CLIENT_SECRET,
      code,
      redirect_uri: `${OAUTH_BASE_URL}${callbackPath}`,
      grant_type: "authorization_code",
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(10000),
  });
  const tokenData = await tokenResp.json() as {
    access_token?: string; refresh_token?: string; expires_in?: number;
    id_token?: string; error?: string; scope?: string;
  };
  if (!tokenData.access_token) throw new Error(tokenData.error || "No access token received");

  // Fetch user info
  const userResp = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
    signal: AbortSignal.timeout(8000),
  });
  const userData = await userResp.json() as { email?: string; name?: string };

  const expiresAt = tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : null;

  upsertOAuthCredential({
    provider: "google",
    source: "web-oauth",
    email: userData.email || null,
    scope: tokenData.scope || "openid email profile",
    access_token: tokenData.access_token,
    refresh_token: tokenData.refresh_token || null,
    expires_at: expiresAt,
  });

  const redirect = stateRow.redirect_to || "/";
  return { redirectTo: appendOAuthQuery(redirect.startsWith("/") ? `${OAUTH_BASE_URL}${redirect}` : redirect, "oauth", "google") };
}

// ---------------------------------------------------------------------------
// OAuth credentials (simplified for CLImpire)
// ---------------------------------------------------------------------------
app.get("/api/oauth/status", (_req, res) => {
  const home = os.homedir();

  // 1. DB-stored OAuth credentials (including web-oauth)
  const rows = db.prepare(
    "SELECT provider, source, email, scope, expires_at, created_at, updated_at, access_token_enc FROM oauth_credentials"
  ).all() as Array<{
    provider: string;
    source: string | null;
    email: string | null;
    scope: string | null;
    expires_at: number | null;
    created_at: number;
    updated_at: number;
    access_token_enc: string | null;
  }>;

  const providers: Record<string, {
    connected: boolean;
    source: string | null;
    email: string | null;
    scope: string | null;
    expires_at: number | null;
    created_at: number;
    updated_at: number;
    webConnectable: boolean;
  }> = {};

  for (const row of rows) {
    providers[row.provider] = {
      connected: true,
      source: row.access_token_enc ? "web-oauth" : (row.source || "db"),
      email: row.email,
      scope: row.scope,
      expires_at: row.expires_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
      webConnectable: row.provider === "github" || row.provider === "google",
    };
  }

  // 2. Detect OAuth-based service credentials from local files
  //    (These are OAuth services like GitHub, Google Cloud — NOT CLI tools)

  // GitHub (gh CLI OAuth — used by Copilot, GitHub integrations)
  if (!providers.github) {
    try {
      const hostsPath = path.join(home, ".config", "gh", "hosts.yml");
      const raw = fs.readFileSync(hostsPath, "utf8");
      const userMatch = raw.match(/user:\s*(\S+)/);
      if (userMatch) {
        const ghUser = userMatch[1];
        const stat = fs.statSync(hostsPath);
        providers.github = {
          connected: true,
          source: "file-detected",
          email: ghUser,
          scope: "github.com",
          expires_at: null,
          created_at: stat.birthtimeMs,
          updated_at: stat.mtimeMs,
          webConnectable: true,
        };
      }
    } catch {}
  }

  // GitHub Copilot (separate OAuth from GitHub)
  if (!providers.copilot) {
    const copilotPaths = [
      path.join(home, ".config", "github-copilot", "hosts.json"),
      path.join(home, ".config", "github-copilot", "apps.json"),
    ];
    for (const cp of copilotPaths) {
      try {
        const raw = JSON.parse(fs.readFileSync(cp, "utf8"));
        if (raw && typeof raw === "object" && Object.keys(raw).length > 0) {
          const stat = fs.statSync(cp);
          const firstKey = Object.keys(raw)[0];
          providers.copilot = {
            connected: true,
            source: "file-detected",
            email: raw[firstKey]?.user ?? null,
            scope: "copilot",
            expires_at: null,
            created_at: stat.birthtimeMs,
            updated_at: stat.mtimeMs,
            webConnectable: false,
          };
          break;
        }
      } catch {}
    }
  }

  // Google Cloud OAuth (gcloud application default credentials)
  if (!providers.google) {
    try {
      const adcPath = path.join(home, ".config", "gcloud", "application_default_credentials.json");
      const raw = JSON.parse(fs.readFileSync(adcPath, "utf8"));
      if (raw?.client_id || raw?.type) {
        const stat = fs.statSync(adcPath);
        providers.google = {
          connected: true,
          source: "file-detected",
          email: raw.client_email ?? raw.account ?? null,
          scope: raw.type ?? "authorized_user",
          expires_at: null,
          created_at: stat.birthtimeMs,
          updated_at: stat.mtimeMs,
          webConnectable: true,
        };
      }
    } catch {}
  }

  // Antigravity
  if (!providers.antigravity) {
    const agPaths = [
      path.join(home, ".antigravity", "auth.json"),
      path.join(home, ".config", "antigravity", "auth.json"),
      path.join(home, ".config", "antigravity", "credentials.json"),
    ];
    for (const ap of agPaths) {
      try {
        const raw = JSON.parse(fs.readFileSync(ap, "utf8"));
        if (raw && typeof raw === "object") {
          const stat = fs.statSync(ap);
          providers.antigravity = {
            connected: true,
            source: "file-detected",
            email: raw.email ?? raw.user ?? null,
            scope: raw.scope ?? null,
            expires_at: raw.expires_at ?? null,
            created_at: stat.birthtimeMs,
            updated_at: stat.mtimeMs,
            webConnectable: false,
          };
          break;
        }
      } catch {}
    }
  }

  // Always include github and google with webConnectable flag
  // webConnectable = true when OAuth client IDs are configured
  const ghConnectable = Boolean(OAUTH_GITHUB_CLIENT_ID);
  const goConnectable = Boolean(OAUTH_GOOGLE_CLIENT_ID);

  if (providers.github) {
    providers.github.webConnectable = ghConnectable;
  } else {
    providers.github = {
      connected: false, source: null, email: null, scope: null,
      expires_at: null, created_at: 0, updated_at: 0, webConnectable: ghConnectable,
    };
  }
  if (providers.google) {
    providers.google.webConnectable = goConnectable;
  } else {
    providers.google = {
      connected: false, source: null, email: null, scope: null,
      expires_at: null, created_at: 0, updated_at: 0, webConnectable: goConnectable,
    };
  }

  res.json({
    storageReady: Boolean(OAUTH_ENCRYPTION_SECRET),
    providers,
  });
});

// GET /api/oauth/start — Begin OAuth flow
app.get("/api/oauth/start", (req, res) => {
  const provider = firstQueryValue(req.query.provider);
  const redirectTo = firstQueryValue(req.query.redirect_to);

  try {
    let authorizeUrl: string;
    if (provider === "github") {
      authorizeUrl = startGitHubOAuth(redirectTo, "/api/oauth/callback/github");
    } else if (provider === "google") {
      authorizeUrl = startGoogleOAuth(redirectTo, "/api/oauth/callback/google");
    } else {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }
    res.redirect(authorizeUrl);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: msg });
  }
});

// GET /api/oauth/callback/github — GitHub OAuth callback
app.get("/api/oauth/callback/github", async (req, res) => {
  const code = firstQueryValue(req.query.code);
  const state = firstQueryValue(req.query.state);
  const error = firstQueryValue(req.query.error);

  if (error || !code || !state) {
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", error || "missing_code");
    return res.redirect(redirectUrl.toString());
  }

  try {
    const result = await handleGitHubCallback(code, state, "/api/oauth/callback/github");
    res.redirect(result.redirectTo);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[OAuth] GitHub callback error:", msg);
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", msg);
    res.redirect(redirectUrl.toString());
  }
});

// GET /api/oauth/callback/google — Google OAuth callback
app.get("/api/oauth/callback/google", async (req, res) => {
  const code = firstQueryValue(req.query.code);
  const state = firstQueryValue(req.query.state);
  const error = firstQueryValue(req.query.error);

  if (error || !code || !state) {
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", error || "missing_code");
    return res.redirect(redirectUrl.toString());
  }

  try {
    const result = await handleGoogleCallback(code, state, "/api/oauth/callback/google");
    res.redirect(result.redirectTo);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[OAuth] Google callback error:", msg);
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", msg);
    res.redirect(redirectUrl.toString());
  }
});

// POST /api/oauth/disconnect — Disconnect a provider
app.post("/api/oauth/disconnect", (req, res) => {
  const provider = (req.body as { provider?: string })?.provider;
  if (!provider || typeof provider !== "string") {
    return res.status(400).json({ error: "provider is required" });
  }
  db.prepare("DELETE FROM oauth_credentials WHERE provider = ?").run(provider);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Git Worktree management endpoints
// ---------------------------------------------------------------------------

// GET /api/tasks/:id/diff — Get diff for review in UI
app.get("/api/tasks/:id/diff", (req, res) => {
  const id = String(req.params.id);
  const wtInfo = taskWorktrees.get(id);
  if (!wtInfo) {
    return res.json({ ok: true, hasWorktree: false, diff: "", stat: "" });
  }

  try {
    const currentBranch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: wtInfo.projectPath, stdio: "pipe", timeout: 5000,
    }).toString().trim();

    const stat = execFileSync("git", ["diff", `${currentBranch}...${wtInfo.branchName}`, "--stat"], {
      cwd: wtInfo.projectPath, stdio: "pipe", timeout: 10000,
    }).toString().trim();

    const diff = execFileSync("git", ["diff", `${currentBranch}...${wtInfo.branchName}`], {
      cwd: wtInfo.projectPath, stdio: "pipe", timeout: 15000,
    }).toString();

    res.json({
      ok: true,
      hasWorktree: true,
      branchName: wtInfo.branchName,
      stat,
      diff: diff.length > 50000 ? diff.slice(0, 50000) + "\n... (truncated)" : diff,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.json({ ok: false, error: msg });
  }
});

// POST /api/tasks/:id/merge — Manually trigger merge
app.post("/api/tasks/:id/merge", (req, res) => {
  const id = String(req.params.id);
  const wtInfo = taskWorktrees.get(id);
  if (!wtInfo) {
    return res.status(404).json({ error: "no_worktree", message: "No worktree found for this task" });
  }

  const result = mergeWorktree(wtInfo.projectPath, id);

  if (result.success) {
    cleanupWorktree(wtInfo.projectPath, id);
    appendTaskLog(id, "system", `Manual merge 완료: ${result.message}`);
    notifyCeo(`수동 병합 완료: ${result.message}`, id);
  } else {
    appendTaskLog(id, "system", `Manual merge 실패: ${result.message}`);
  }

  res.json({ ok: result.success, message: result.message, conflicts: result.conflicts });
});

// POST /api/tasks/:id/discard — Discard worktree changes (abandon branch)
app.post("/api/tasks/:id/discard", (req, res) => {
  const id = String(req.params.id);
  const wtInfo = taskWorktrees.get(id);
  if (!wtInfo) {
    return res.status(404).json({ error: "no_worktree", message: "No worktree found for this task" });
  }

  cleanupWorktree(wtInfo.projectPath, id);
  appendTaskLog(id, "system", "Worktree discarded (changes abandoned)");
  notifyCeo(`작업 브랜치가 폐기되었습니다: climpire/${id.slice(0, 8)}`, id);

  res.json({ ok: true, message: "Worktree discarded" });
});

// GET /api/worktrees — List all active worktrees
app.get("/api/worktrees", (_req, res) => {
  const entries: Array<{ taskId: string; branchName: string; worktreePath: string; projectPath: string }> = [];
  for (const [taskId, info] of taskWorktrees) {
    entries.push({ taskId, ...info });
  }
  res.json({ ok: true, worktrees: entries });
});

// ---------------------------------------------------------------------------
// CLI Usage stats (real provider API usage, persisted in SQLite)
// ---------------------------------------------------------------------------

// Read cached usage from SQLite
function readCliUsageFromDb(): Record<string, CliUsageEntry> {
  const rows = db.prepare("SELECT provider, data_json FROM cli_usage_cache").all() as Array<{ provider: string; data_json: string }>;
  const usage: Record<string, CliUsageEntry> = {};
  for (const row of rows) {
    try { usage[row.provider] = JSON.parse(row.data_json); } catch { /* skip corrupt */ }
  }
  return usage;
}

// Fetch real usage from provider APIs and persist to SQLite
async function refreshCliUsageData(): Promise<Record<string, CliUsageEntry>> {
  const providers = ["claude", "codex", "gemini", "copilot", "antigravity"];
  const usage: Record<string, CliUsageEntry> = {};

  const fetchMap: Record<string, () => Promise<CliUsageEntry>> = {
    claude: fetchClaudeUsage,
    codex: fetchCodexUsage,
    gemini: fetchGeminiUsage,
  };

  const fetches = providers.map(async (p) => {
    const tool = CLI_TOOLS.find((t) => t.name === p);
    if (!tool) {
      usage[p] = { windows: [], error: "not_implemented" };
      return;
    }
    if (!tool.checkAuth()) {
      usage[p] = { windows: [], error: "unauthenticated" };
      return;
    }
    const fetcher = fetchMap[p];
    if (fetcher) {
      usage[p] = await fetcher();
    } else {
      usage[p] = { windows: [], error: "not_implemented" };
    }
  });

  await Promise.all(fetches);

  // Persist to SQLite
  const upsert = db.prepare(
    "INSERT INTO cli_usage_cache (provider, data_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(provider) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at"
  );
  const now = nowMs();
  for (const [p, entry] of Object.entries(usage)) {
    upsert.run(p, JSON.stringify(entry), now);
  }

  return usage;
}

// GET: read from SQLite cache; if empty, fetch and populate first
app.get("/api/cli-usage", async (_req, res) => {
  let usage = readCliUsageFromDb();
  if (Object.keys(usage).length === 0) {
    usage = await refreshCliUsageData();
  }
  res.json({ ok: true, usage });
});

// POST: trigger real API fetches, update SQLite, broadcast to all clients
app.post("/api/cli-usage/refresh", async (_req, res) => {
  try {
    const usage = await refreshCliUsageData();
    broadcast("cli_usage_update", usage);
    res.json({ ok: true, usage });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ---------------------------------------------------------------------------
// Production: serve React UI from dist/
// ---------------------------------------------------------------------------
if (isProduction) {
  app.use(express.static(distDir));
  // SPA fallback: serve index.html for non-API routes (Express 5 named wildcard)
  app.get("/{*splat}", (req, res) => {
    if (req.path.startsWith("/api/") || req.path === "/health" || req.path === "/healthz") {
      return res.status(404).json({ error: "not_found" });
    }
    res.sendFile(path.join(distDir, "index.html"));
  });
}

// ---------------------------------------------------------------------------
// Start HTTP server + WebSocket
// ---------------------------------------------------------------------------
const server = app.listen(PORT, HOST, () => {
  console.log(`[CLImpire] v${PKG_VERSION} listening on http://${HOST}:${PORT} (db: ${dbPath})`);
  if (isProduction) {
    console.log(`[CLImpire] mode: production (serving UI from ${distDir})`);
  } else {
    console.log(`[CLImpire] mode: development (UI served by Vite on separate port)`);
  }
});

// WebSocket server on same HTTP server
const wss = new WebSocketServer({ server });

wss.on("connection", (ws: WebSocket, _req: IncomingMessage) => {
  wsClients.add(ws);
  console.log(`[CLImpire] WebSocket client connected (total: ${wsClients.size})`);

  // Send initial state to the newly connected client
  ws.send(JSON.stringify({
    type: "connected",
    payload: {
      version: PKG_VERSION,
      app: "CLImpire",
    },
    ts: nowMs(),
  }));

  ws.on("close", () => {
    wsClients.delete(ws);
    console.log(`[CLImpire] WebSocket client disconnected (total: ${wsClients.size})`);
  });

  ws.on("error", () => {
    wsClients.delete(ws);
  });
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------
function gracefulShutdown(signal: string): void {
  console.log(`\n[CLImpire] ${signal} received. Shutting down gracefully...`);

  // Stop all active CLI processes
  for (const [taskId, child] of activeProcesses) {
    console.log(`[CLImpire] Stopping process for task ${taskId} (pid: ${child.pid})`);
    if (child.pid) {
      killPidTree(child.pid);
    }
    activeProcesses.delete(taskId);

    // Reset agent status for running tasks
    const task = db.prepare("SELECT assigned_agent_id FROM tasks WHERE id = ?").get(taskId) as {
      assigned_agent_id: string | null;
    } | undefined;
    if (task?.assigned_agent_id) {
      db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?")
        .run(task.assigned_agent_id);
    }
    db.prepare("UPDATE tasks SET status = 'cancelled', updated_at = ? WHERE id = ? AND status = 'in_progress'")
      .run(nowMs(), taskId);
  }

  // Close all WebSocket connections
  for (const ws of wsClients) {
    ws.close(1001, "Server shutting down");
  }
  wsClients.clear();

  // Close WebSocket server
  wss.close(() => {
    // Close HTTP server
    server.close(() => {
      // Close database
      try {
        db.close();
      } catch { /* ignore */ }
      console.log("[CLImpire] Shutdown complete.");
      process.exit(0);
    });
  });

  // Force exit after 5 seconds if graceful shutdown hangs
  setTimeout(() => {
    console.error("[CLImpire] Forced exit after timeout.");
    process.exit(1);
  }, 5000).unref();
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// nodemon sends SIGUSR2 on restart — close DB cleanly before it kills us
process.once("SIGUSR2", () => {
  try { db.close(); } catch { /* ignore */ }
  process.kill(process.pid, "SIGUSR2");
});
