import type {
  Department, Agent, Task, TaskLog, Message,
  CliStatusMap, CompanyStats, CompanySettings,
  TaskStatus, TaskType, CliProvider, AgentRole,
  MessageType, ReceiverType
} from './types';

const base = '';

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${base}${url}`, init);
  if (!r.ok) {
    const body = await r.json().catch(() => null);
    throw new Error(body?.error ?? body?.message ?? `Request failed: ${r.status}`);
  }
  return r.json();
}

function post(url: string, body?: unknown) {
  return request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function patch(url: string, body: unknown) {
  return request(url, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function put(url: string, body: unknown) {
  return request(url, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function del(url: string) {
  return request(url, { method: 'DELETE' });
}

// Departments
export async function getDepartments(): Promise<Department[]> {
  const j = await request<{ departments: Department[] }>('/api/departments');
  return j.departments;
}

export async function getDepartment(id: string): Promise<{ department: Department; agents: Agent[] }> {
  return request(`/api/departments/${id}`);
}

// Agents
export async function getAgents(): Promise<Agent[]> {
  const j = await request<{ agents: Agent[] }>('/api/agents');
  return j.agents;
}

export async function getAgent(id: string): Promise<Agent> {
  const j = await request<{ agent: Agent }>(`/api/agents/${id}`);
  return j.agent;
}

export async function updateAgent(id: string, data: Partial<Pick<Agent, 'status' | 'current_task_id' | 'department_id' | 'role' | 'cli_provider' | 'personality'>>): Promise<void> {
  await patch(`/api/agents/${id}`, data);
}

// Tasks
export async function getTasks(filters?: { status?: TaskStatus; department_id?: string; agent_id?: string }): Promise<Task[]> {
  const params = new URLSearchParams();
  if (filters?.status) params.set('status', filters.status);
  if (filters?.department_id) params.set('department_id', filters.department_id);
  if (filters?.agent_id) params.set('agent_id', filters.agent_id);
  const q = params.toString();
  const j = await request<{ tasks: Task[] }>(`/api/tasks${q ? '?' + q : ''}`);
  return j.tasks;
}

export async function getTask(id: string): Promise<{ task: Task; logs: TaskLog[] }> {
  return request(`/api/tasks/${id}`);
}

export async function createTask(input: {
  title: string;
  description?: string;
  department_id?: string;
  task_type?: TaskType;
  priority?: number;
  project_path?: string;
}): Promise<string> {
  const j = await post('/api/tasks', input) as { id: string };
  return j.id;
}

export async function updateTask(id: string, data: Partial<Pick<Task, 'title' | 'description' | 'status' | 'priority' | 'task_type' | 'department_id' | 'project_path'>>): Promise<void> {
  await patch(`/api/tasks/${id}`, data);
}

export async function deleteTask(id: string): Promise<void> {
  await del(`/api/tasks/${id}`);
}

export async function assignTask(id: string, agentId: string): Promise<void> {
  await post(`/api/tasks/${id}/assign`, { agent_id: agentId });
}

export async function runTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/run`);
}

export async function stopTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/stop`, { mode: 'cancel' });
}

export async function pauseTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/stop`, { mode: 'pause' });
}

export async function resumeTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/resume`);
}

// Messages
export async function getMessages(params: { receiver_type?: ReceiverType; receiver_id?: string; limit?: number }): Promise<Message[]> {
  const sp = new URLSearchParams();
  if (params.receiver_type) sp.set('receiver_type', params.receiver_type);
  if (params.receiver_id) sp.set('receiver_id', params.receiver_id);
  if (params.limit) sp.set('limit', String(params.limit));
  const q = sp.toString();
  const j = await request<{ messages: Message[] }>(`/api/messages${q ? '?' + q : ''}`);
  return j.messages;
}

export async function sendMessage(input: {
  receiver_type: ReceiverType;
  receiver_id?: string;
  content: string;
  message_type?: MessageType;
  task_id?: string;
}): Promise<string> {
  const j = await post('/api/messages', { sender_type: 'ceo', ...input }) as { id: string };
  return j.id;
}

export async function sendAnnouncement(content: string): Promise<string> {
  const j = await post('/api/announcements', { content }) as { id: string };
  return j.id;
}

export async function clearMessages(agentId?: string): Promise<void> {
  const params = new URLSearchParams();
  if (agentId) {
    params.set('agent_id', agentId);
  } else {
    params.set('scope', 'announcements');
  }
  await del(`/api/messages?${params.toString()}`);
}

// Terminal
export async function getTerminal(id: string, lines?: number, pretty?: boolean): Promise<{
  ok: boolean;
  exists: boolean;
  path: string;
  text: string;
  task_logs?: Array<{ id: number; kind: string; message: string; created_at: number }>;
}> {
  const params = new URLSearchParams();
  if (lines) params.set('lines', String(lines));
  if (pretty) params.set('pretty', '1');
  const q = params.toString();
  return request(`/api/tasks/${id}/terminal${q ? '?' + q : ''}`);
}

// CLI Status
export async function getCliStatus(refresh?: boolean): Promise<CliStatusMap> {
  const q = refresh ? '?refresh=1' : '';
  const j = await request<{ providers: CliStatusMap }>(`/api/cli-status${q}`);
  return j.providers;
}

// Stats
export async function getStats(): Promise<CompanyStats> {
  const j = await request<{ stats: CompanyStats }>('/api/stats');
  return j.stats;
}

// Settings
export async function getSettings(): Promise<CompanySettings> {
  const j = await request<{ settings: CompanySettings }>('/api/settings');
  return j.settings;
}

export async function saveSettings(settings: CompanySettings): Promise<void> {
  await put('/api/settings', settings);
}

// OAuth
export interface OAuthProviderStatus {
  connected: boolean;
  source: string | null;
  email: string | null;
  scope: string | null;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface OAuthStatus {
  storageReady: boolean;
  providers: Record<string, OAuthProviderStatus>;
}

export async function getOAuthStatus(): Promise<OAuthStatus> {
  return request<OAuthStatus>('/api/oauth/status');
}

// Git Worktree management
export interface TaskDiffResult {
  ok: boolean;
  hasWorktree?: boolean;
  branchName?: string;
  stat?: string;
  diff?: string;
  error?: string;
}

export interface MergeResult {
  ok: boolean;
  message: string;
  conflicts?: string[];
}

export interface WorktreeEntry {
  taskId: string;
  branchName: string;
  worktreePath: string;
  projectPath: string;
}

export async function getTaskDiff(id: string): Promise<TaskDiffResult> {
  return request<TaskDiffResult>(`/api/tasks/${id}/diff`);
}

export async function mergeTask(id: string): Promise<MergeResult> {
  return post(`/api/tasks/${id}/merge`) as Promise<MergeResult>;
}

export async function discardTask(id: string): Promise<{ ok: boolean; message: string }> {
  return post(`/api/tasks/${id}/discard`) as Promise<{ ok: boolean; message: string }>;
}

export async function getWorktrees(): Promise<{ ok: boolean; worktrees: WorktreeEntry[] }> {
  return request<{ ok: boolean; worktrees: WorktreeEntry[] }>('/api/worktrees');
}
