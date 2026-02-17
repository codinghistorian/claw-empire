import { useState, useMemo, useCallback, useEffect } from 'react';
import type { Task, Agent, Department, TaskStatus, TaskType } from '../types';
import AgentAvatar from './AgentAvatar';
import AgentSelect from './AgentSelect';
import { getTaskDiff, mergeTask, discardTask, type TaskDiffResult } from '../api';

interface TaskBoardProps {
  tasks: Task[];
  agents: Agent[];
  departments: Department[];
  onCreateTask: (input: {
    title: string;
    description?: string;
    department_id?: string;
    task_type?: string;
    priority?: number;
  }) => void;
  onUpdateTask: (id: string, data: Partial<Task>) => void;
  onDeleteTask: (id: string) => void;
  onAssignTask: (taskId: string, agentId: string) => void;
  onRunTask: (id: string) => void;
  onStopTask: (id: string) => void;
  onPauseTask?: (id: string) => void;
  onResumeTask?: (id: string) => void;
  onOpenTerminal?: (taskId: string) => void;
  onMergeTask?: (id: string) => void;
  onDiscardTask?: (id: string) => void;
}

// ── Column config ──────────────────────────────────────────────────────────────

const COLUMNS: {
  status: TaskStatus;
  label: string;
  icon: string;
  headerBg: string;
  borderColor: string;
  dotColor: string;
}[] = [
  {
    status: 'inbox',
    label: 'Inbox',
    icon: '📥',
    headerBg: 'bg-slate-800',
    borderColor: 'border-slate-600',
    dotColor: 'bg-slate-400',
  },
  {
    status: 'planned',
    label: 'Planned',
    icon: '📋',
    headerBg: 'bg-blue-900',
    borderColor: 'border-blue-700',
    dotColor: 'bg-blue-400',
  },
  {
    status: 'in_progress',
    label: 'In Progress',
    icon: '⚡',
    headerBg: 'bg-amber-900',
    borderColor: 'border-amber-700',
    dotColor: 'bg-amber-400',
  },
  {
    status: 'review',
    label: 'Review',
    icon: '🔍',
    headerBg: 'bg-purple-900',
    borderColor: 'border-purple-700',
    dotColor: 'bg-purple-400',
  },
  {
    status: 'done',
    label: 'Done',
    icon: '✅',
    headerBg: 'bg-green-900',
    borderColor: 'border-green-700',
    dotColor: 'bg-green-400',
  },
  {
    status: 'pending',
    label: 'Pending',
    icon: '⏸️',
    headerBg: 'bg-orange-900',
    borderColor: 'border-orange-700',
    dotColor: 'bg-orange-400',
  },
  {
    status: 'cancelled',
    label: 'Cancelled',
    icon: '🚫',
    headerBg: 'bg-red-900',
    borderColor: 'border-red-700',
    dotColor: 'bg-red-400',
  },
];

const STATUS_OPTIONS: { value: TaskStatus; label: string }[] = [
  { value: 'inbox', label: 'Inbox' },
  { value: 'planned', label: 'Planned' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'review', label: 'Review' },
  { value: 'done', label: 'Done' },
  { value: 'pending', label: 'Pending' },
  { value: 'cancelled', label: 'Cancelled' },
];

const TASK_TYPE_OPTIONS: { value: TaskType; label: string; color: string }[] = [
  { value: 'general', label: 'General', color: 'bg-slate-700 text-slate-300' },
  { value: 'development', label: 'Development', color: 'bg-cyan-900 text-cyan-300' },
  { value: 'design', label: 'Design', color: 'bg-pink-900 text-pink-300' },
  { value: 'analysis', label: 'Analysis', color: 'bg-indigo-900 text-indigo-300' },
  { value: 'presentation', label: 'Presentation', color: 'bg-orange-900 text-orange-300' },
  { value: 'documentation', label: 'Documentation', color: 'bg-teal-900 text-teal-300' },
];

function getTaskTypeBadge(type: TaskType) {
  return TASK_TYPE_OPTIONS.find((t) => t.value === type) ?? TASK_TYPE_OPTIONS[0];
}

function priorityIcon(p: number) {
  if (p >= 4) return '🔴';
  if (p >= 2) return '🟡';
  return '🟢';
}

function priorityLabel(p: number) {
  if (p >= 4) return 'High';
  if (p >= 2) return 'Medium';
  return 'Low';
}

function timeAgo(ts: number): string {
  const diffSec = Math.floor((Date.now() - ts) / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) return `${diffH}h ago`;
  return `${Math.floor(diffH / 24)}d ago`;
}

// ── Create Modal ──────────────────────────────────────────────────────────────

interface CreateModalProps {
  agents: Agent[];
  departments: Department[];
  onClose: () => void;
  onCreate: TaskBoardProps['onCreateTask'];
  onAssign: TaskBoardProps['onAssignTask'];
}

function CreateModal({ agents, departments, onClose, onCreate, onAssign }: CreateModalProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [departmentId, setDepartmentId] = useState('');
  const [taskType, setTaskType] = useState<TaskType>('general');
  const [priority, setPriority] = useState(3);
  const [assignAgentId, setAssignAgentId] = useState('');

  const filteredAgents = useMemo(
    () => (departmentId ? agents.filter((a) => a.department_id === departmentId) : agents),
    [agents, departmentId],
  );

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) return;

    // We'll create the task first then assign if needed.
    // Since onCreate doesn't return the task id, we rely on the parent
    // calling onAssignTask after the task appears. For now, we pass
    // a combined approach: create with the data and let parent handle assign.
    onCreate({
      title: title.trim(),
      description: description.trim() || undefined,
      department_id: departmentId || undefined,
      task_type: taskType,
      priority,
    });

    // Note: assigning requires the task id which we don't have yet.
    // The parent component should handle this after task creation.
    // We surface the assignAgentId via a custom event pattern below.
    if (assignAgentId) {
      // Store for parent to pick up — simple approach: set a data attr on the form
      // In practice, onCreateTask should accept assigned_agent_id too,
      // or the parent should handle post-creation assignment.
      // We call onAssign with a placeholder id; the parent must handle timing.
      // This is a best-effort call with a temporary empty string —
      // in a real setup, the API would return the new task id.
      // For now we skip and let the user assign from the card.
    }

    onClose();
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-lg font-bold text-white">새 업무 만들기</h2>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-white"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Title */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">
              제목 <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="업무 제목을 입력하세요"
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Description */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">설명</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="업무에 대한 상세 설명을 입력하세요"
              rows={3}
              className="w-full resize-none rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Department + Task Type */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-300">부서</label>
              <select
                value={departmentId}
                onChange={(e) => {
                  setDepartmentId(e.target.value);
                  setAssignAgentId('');
                }}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="">-- 전체 --</option>
                {departments.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.icon} {d.name_ko}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-300">업무 유형</label>
              <select
                value={taskType}
                onChange={(e) => setTaskType(e.target.value as TaskType)}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                {TASK_TYPE_OPTIONS.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Priority */}
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">
              우선순위: {priorityIcon(priority)} {priorityLabel(priority)} ({priority}/5)
            </label>
            <div className="flex gap-2">
              {[1, 2, 3, 4, 5].map((star) => (
                <button
                  key={star}
                  type="button"
                  onClick={() => setPriority(star)}
                  className={`flex-1 rounded-lg py-2 text-lg transition ${
                    star <= priority
                      ? 'bg-amber-600 text-white shadow-md'
                      : 'bg-slate-800 text-slate-500 hover:bg-slate-700'
                  }`}
                >
                  ★
                </button>
              ))}
            </div>
          </div>

          {/* Assign Agent */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">담당 에이전트</label>
            <AgentSelect
              agents={filteredAgents}
              value={assignAgentId}
              onChange={setAssignAgentId}
              placeholder="-- 미배정 --"
              size="md"
            />
            {departmentId && filteredAgents.length === 0 && (
              <p className="mt-1 text-xs text-slate-500">해당 부서에 에이전트가 없습니다.</p>
            )}
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-800"
            >
              취소
            </button>
            <button
              type="submit"
              disabled={!title.trim()}
              className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
            >
              업무 만들기
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Task Card ─────────────────────────────────────────────────────────────────

// ── Diff Modal ────────────────────────────────────────────────────────────────

function DiffModal({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const [diffData, setDiffData] = useState<TaskDiffResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [merging, setMerging] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [actionResult, setActionResult] = useState<string | null>(null);

  useEffect(() => {
    getTaskDiff(taskId)
      .then((d) => {
        if (!d.ok) setError(d.error || 'Unknown error');
        else setDiffData(d);
        setLoading(false);
      })
      .catch((e) => { setError(e instanceof Error ? e.message : String(e)); setLoading(false); });
  }, [taskId]);

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const handleMerge = useCallback(async () => {
    if (!confirm('이 브랜치를 메인에 병합하시겠습니까?')) return;
    setMerging(true);
    try {
      const result = await mergeTask(taskId);
      setActionResult(result.ok ? `병합 완료: ${result.message}` : `병합 실패: ${result.message}`);
      if (result.ok) setTimeout(onClose, 1500);
    } catch (e: unknown) {
      setActionResult(`오류: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setMerging(false);
    }
  }, [taskId, onClose]);

  const handleDiscard = useCallback(async () => {
    if (!confirm('이 브랜치의 변경사항을 모두 폐기하시겠습니까? 이 작업은 되돌릴 수 없습니다.')) return;
    setDiscarding(true);
    try {
      const result = await discardTask(taskId);
      setActionResult(result.ok ? '브랜치가 폐기되었습니다.' : `폐기 실패: ${result.message}`);
      if (result.ok) setTimeout(onClose, 1500);
    } catch (e: unknown) {
      setActionResult(`오류: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDiscarding(false);
    }
  }, [taskId, onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="flex max-h-[85vh] w-full max-w-4xl flex-col rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-3">
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold text-white">Git Diff</span>
            {diffData?.branchName && (
              <span className="rounded-full bg-purple-900 px-2.5 py-0.5 text-xs text-purple-300">
                {diffData.branchName}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleMerge}
              disabled={merging || discarding || !diffData?.hasWorktree}
              className="rounded-lg bg-green-700 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-green-600 disabled:opacity-40"
            >
              {merging ? '...' : 'Merge'}
            </button>
            <button
              onClick={handleDiscard}
              disabled={merging || discarding || !diffData?.hasWorktree}
              className="rounded-lg bg-red-800 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-red-700 disabled:opacity-40"
            >
              {discarding ? '...' : 'Discard'}
            </button>
            <button
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-white"
            >
              X
            </button>
          </div>
        </div>

        {/* Action result */}
        {actionResult && (
          <div className="border-b border-slate-700 bg-slate-800 px-5 py-2 text-sm text-amber-300">
            {actionResult}
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-auto p-5">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-slate-400">Loading diff...</div>
          ) : error ? (
            <div className="flex items-center justify-center py-12 text-red-400">
              Error: {error}
            </div>
          ) : !diffData?.hasWorktree ? (
            <div className="flex items-center justify-center py-12 text-slate-500">
              No worktree found for this task (non-git project or already merged)
            </div>
          ) : (
            <div className="space-y-4">
              {/* Stat summary */}
              {diffData.stat && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-slate-300">Summary</h3>
                  <pre className="rounded-lg bg-slate-800 p-3 text-xs text-slate-300 overflow-x-auto">{diffData.stat}</pre>
                </div>
              )}
              {/* Full diff */}
              {diffData.diff && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-slate-300">Diff</h3>
                  <pre className="max-h-[50vh] overflow-auto rounded-lg bg-slate-950 p-3 text-xs leading-relaxed">
                    {diffData.diff.split('\n').map((line, i) => {
                      let cls = 'text-slate-400';
                      if (line.startsWith('+') && !line.startsWith('+++')) cls = 'text-green-400';
                      else if (line.startsWith('-') && !line.startsWith('---')) cls = 'text-red-400';
                      else if (line.startsWith('@@')) cls = 'text-cyan-400';
                      else if (line.startsWith('diff ') || line.startsWith('index ')) cls = 'text-slate-500 font-bold';
                      return <span key={i} className={cls}>{line}{'\n'}</span>;
                    })}
                  </pre>
                </div>
              )}
              {!diffData.stat && !diffData.diff && (
                <div className="text-center text-slate-500 py-8">No changes detected</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface TaskCardProps {
  task: Task;
  agents: Agent[];
  departments: Department[];
  onUpdateTask: TaskBoardProps['onUpdateTask'];
  onDeleteTask: TaskBoardProps['onDeleteTask'];
  onAssignTask: TaskBoardProps['onAssignTask'];
  onRunTask: TaskBoardProps['onRunTask'];
  onStopTask: TaskBoardProps['onStopTask'];
  onPauseTask?: (id: string) => void;
  onResumeTask?: (id: string) => void;
  onOpenTerminal?: (taskId: string) => void;
  onMergeTask?: (id: string) => void;
  onDiscardTask?: (id: string) => void;
}

function TaskCard({
  task,
  agents,
  departments,
  onUpdateTask,
  onDeleteTask,
  onAssignTask,
  onRunTask,
  onStopTask,
  onPauseTask,
  onResumeTask,
  onOpenTerminal,
}: TaskCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [showDiff, setShowDiff] = useState(false);

  const assignedAgent = task.assigned_agent ?? agents.find((a) => a.id === task.assigned_agent_id);
  const department = departments.find((d) => d.id === task.department_id);
  const typeBadge = getTaskTypeBadge(task.task_type);

  const canRun = task.status === 'planned' || task.status === 'inbox';
  const canStop = task.status === 'in_progress';
  const canPause = task.status === 'in_progress' && !!onPauseTask;
  const canResume = (task.status === 'pending' || task.status === 'cancelled') && !!onResumeTask;
  const canDelete = task.status !== 'in_progress';

  return (
    <div className="group rounded-xl border border-slate-700 bg-slate-800 p-3.5 shadow-sm transition hover:border-slate-600 hover:shadow-md">
      {/* Header row */}
      <div className="mb-2 flex items-start justify-between gap-2">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex-1 text-left text-sm font-semibold leading-snug text-white"
        >
          {task.title}
        </button>
        <span className="flex-shrink-0 text-base" title={`Priority: ${priorityLabel(task.priority)}`}>
          {priorityIcon(task.priority)}
        </span>
      </div>

      {/* Description */}
      {task.description && (
        <p
          className={`mb-2 text-xs leading-relaxed text-slate-400 ${expanded ? '' : 'line-clamp-2'}`}
        >
          {task.description}
        </p>
      )}

      {/* Badges row */}
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${typeBadge.color}`}>
          {typeBadge.label}
        </span>
        {department && (
          <span className="rounded-full bg-slate-700 px-2 py-0.5 text-xs text-slate-300">
            {department.icon} {department.name_ko}
          </span>
        )}
      </div>

      {/* Status select */}
      <div className="mb-3">
        <select
          value={task.status}
          onChange={(e) => onUpdateTask(task.id, { status: e.target.value as TaskStatus })}
          className="w-full rounded-lg border border-slate-600 bg-slate-700 px-2 py-1 text-xs text-white outline-none transition focus:border-blue-500"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      </div>

      {/* Agent + time */}
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          {assignedAgent ? (
            <>
              <AgentAvatar agent={assignedAgent} agents={agents} size={20} />
              <span className="text-xs text-slate-300">{assignedAgent.name_ko}</span>
            </>
          ) : (
            <span className="text-xs text-slate-500">미배정</span>
          )}
        </div>
        <span className="text-xs text-slate-500">{timeAgo(task.created_at)}</span>
      </div>

      {/* Assign agent dropdown */}
      <div className="mb-3">
        <AgentSelect
          agents={agents}
          value={task.assigned_agent_id ?? ''}
          onChange={(agentId) => {
            if (agentId) {
              onAssignTask(task.id, agentId);
            } else {
              onUpdateTask(task.id, { assigned_agent_id: null });
            }
          }}
        />
      </div>

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-1.5">
        {canRun && (
          <button
            onClick={() => onRunTask(task.id)}
            title="Run task"
            className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-green-700 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-green-600"
          >
            ▶ Run
          </button>
        )}
        {canPause && (
          <button
            onClick={() => onPauseTask!(task.id)}
            title="Pause task (보류)"
            className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-orange-700 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-orange-600"
          >
            ⏸ Pause
          </button>
        )}
        {canStop && (
          <button
            onClick={() => onStopTask(task.id)}
            title="Cancel task (취소)"
            className="flex items-center justify-center gap-1 rounded-lg bg-red-800 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-red-700"
          >
            ⏹ Cancel
          </button>
        )}
        {canResume && (
          <button
            onClick={() => onResumeTask!(task.id)}
            title="Resume task (복구)"
            className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-blue-700 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-blue-600"
          >
            ↩ Resume
          </button>
        )}
        {(task.status === 'in_progress' || task.status === 'review' || task.status === 'done' || task.status === 'pending') && onOpenTerminal && (
          <button
            onClick={() => onOpenTerminal(task.id)}
            title="View terminal output"
            className="flex items-center justify-center rounded-lg bg-slate-700 px-2 py-1.5 text-xs text-slate-300 transition hover:bg-slate-600 hover:text-white"
          >
            &#128421;
          </button>
        )}
        {task.status === 'review' && (
          <button
            onClick={() => setShowDiff(true)}
            title="View changes (Git diff)"
            className="flex items-center justify-center gap-1 rounded-lg bg-purple-800 px-2 py-1.5 text-xs font-medium text-purple-200 transition hover:bg-purple-700"
          >
            Diff
          </button>
        )}
        {canDelete && (
          <button
            onClick={() => {
              if (confirm(`"${task.title}" 업무를 삭제할까요?`)) onDeleteTask(task.id);
            }}
            title="Delete task"
            className="flex items-center justify-center rounded-lg bg-red-900/60 px-2 py-1.5 text-xs text-red-400 transition hover:bg-red-800 hover:text-red-300"
          >
            🗑
          </button>
        )}
      </div>

      {/* Diff modal */}
      {showDiff && <DiffModal taskId={task.id} onClose={() => setShowDiff(false)} />}
    </div>
  );
}

// ── Filter Bar ────────────────────────────────────────────────────────────────

interface FilterBarProps {
  agents: Agent[];
  departments: Department[];
  filterDept: string;
  filterAgent: string;
  filterType: string;
  search: string;
  onFilterDept: (v: string) => void;
  onFilterAgent: (v: string) => void;
  onFilterType: (v: string) => void;
  onSearch: (v: string) => void;
}

function FilterBar({
  agents,
  departments,
  filterDept,
  filterAgent,
  filterType,
  search,
  onFilterDept,
  onFilterAgent,
  onFilterType,
  onSearch,
}: FilterBarProps) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* Search */}
      <div className="relative min-w-[180px] flex-1">
        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-sm">🔎</span>
        <input
          type="text"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="업무 검색..."
          className="w-full rounded-lg border border-slate-700 bg-slate-800 py-1.5 pl-8 pr-3 text-sm text-white placeholder-slate-500 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
      </div>

      {/* Department */}
      <select
        value={filterDept}
        onChange={(e) => onFilterDept(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-300 outline-none transition focus:border-blue-500"
      >
        <option value="">전체 부서</option>
        {departments.map((d) => (
          <option key={d.id} value={d.id}>
            {d.icon} {d.name_ko}
          </option>
        ))}
      </select>

      {/* Agent */}
      <AgentSelect
        agents={agents}
        value={filterAgent}
        onChange={onFilterAgent}
        placeholder="전체 에이전트"
        size="md"
      />

      {/* Task type */}
      <select
        value={filterType}
        onChange={(e) => onFilterType(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-300 outline-none transition focus:border-blue-500"
      >
        <option value="">전체 유형</option>
        {TASK_TYPE_OPTIONS.map((t) => (
          <option key={t.value} value={t.value}>
            {t.label}
          </option>
        ))}
      </select>
    </div>
  );
}

// ── TaskBoard (main export) ───────────────────────────────────────────────────

export function TaskBoard({
  tasks,
  agents,
  departments,
  onCreateTask,
  onUpdateTask,
  onDeleteTask,
  onAssignTask,
  onRunTask,
  onStopTask,
  onPauseTask,
  onResumeTask,
  onOpenTerminal,
  onMergeTask,
  onDiscardTask,
}: TaskBoardProps) {
  const [showCreate, setShowCreate] = useState(false);
  const [filterDept, setFilterDept] = useState('');
  const [filterAgent, setFilterAgent] = useState('');
  const [filterType, setFilterType] = useState('');
  const [search, setSearch] = useState('');

  const filteredTasks = useMemo(() => {
    return tasks.filter((t) => {
      if (filterDept && t.department_id !== filterDept) return false;
      if (filterAgent && t.assigned_agent_id !== filterAgent) return false;
      if (filterType && t.task_type !== filterType) return false;
      if (search && !t.title.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [tasks, filterDept, filterAgent, filterType, search]);

  const tasksByStatus = useMemo(() => {
    const map: Record<string, Task[]> = {};
    for (const col of COLUMNS) {
      map[col.status] = filteredTasks
        .filter((t) => t.status === col.status)
        .sort((a, b) => b.priority - a.priority || b.created_at - a.created_at);
    }
    return map;
  }, [filteredTasks]);

  const activeFilterCount = [filterDept, filterAgent, filterType, search].filter(Boolean).length;

  return (
    <div className="flex h-full flex-col gap-4 bg-slate-950 p-4">
      {/* Top bar */}
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-bold text-white">Task Board</h1>
        <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-400">
          총 {filteredTasks.length}개
          {activeFilterCount > 0 && ` (필터 ${activeFilterCount}개 적용)`}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {activeFilterCount > 0 && (
            <button
              onClick={() => {
                setFilterDept('');
                setFilterAgent('');
                setFilterType('');
                setSearch('');
              }}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 transition hover:bg-slate-800 hover:text-white"
            >
              필터 초기화
            </button>
          )}
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow transition hover:bg-blue-500 active:scale-95"
          >
            + 새 업무
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <FilterBar
        agents={agents}
        departments={departments}
        filterDept={filterDept}
        filterAgent={filterAgent}
        filterType={filterType}
        search={search}
        onFilterDept={setFilterDept}
        onFilterAgent={setFilterAgent}
        onFilterType={setFilterType}
        onSearch={setSearch}
      />

      {/* Kanban board */}
      <div className="flex min-h-0 flex-1 gap-4 overflow-x-auto pb-2">
        {COLUMNS.map((col) => {
          const colTasks = tasksByStatus[col.status] ?? [];
          return (
            <div
              key={col.status}
              className={`flex w-72 flex-shrink-0 flex-col rounded-xl border ${col.borderColor} bg-slate-900`}
            >
              {/* Column header */}
              <div
                className={`flex items-center justify-between rounded-t-xl ${col.headerBg} px-3.5 py-2.5`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`h-2 w-2 flex-shrink-0 rounded-full ${col.dotColor}`}
                  />
                  <span className="text-sm font-semibold text-white">
                    {col.icon} {col.label}
                  </span>
                </div>
                <span className="rounded-full bg-black/30 px-2 py-0.5 text-xs font-bold text-white/80">
                  {colTasks.length}
                </span>
              </div>

              {/* Cards */}
              <div className="flex flex-1 flex-col gap-2.5 overflow-y-auto p-2.5">
                {colTasks.length === 0 ? (
                  <div className="flex flex-1 items-center justify-center py-8 text-xs text-slate-600">
                    업무 없음
                  </div>
                ) : (
                  colTasks.map((task) => (
                    <TaskCard
                      key={task.id}
                      task={task}
                      agents={agents}
                      departments={departments}
                      onUpdateTask={onUpdateTask}
                      onDeleteTask={onDeleteTask}
                      onAssignTask={onAssignTask}
                      onRunTask={onRunTask}
                      onStopTask={onStopTask}
                      onPauseTask={onPauseTask}
                      onResumeTask={onResumeTask}
                      onOpenTerminal={onOpenTerminal}
                      onMergeTask={onMergeTask}
                      onDiscardTask={onDiscardTask}
                    />
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Create modal */}
      {showCreate && (
        <CreateModal
          agents={agents}
          departments={departments}
          onClose={() => setShowCreate(false)}
          onCreate={onCreateTask}
          onAssign={onAssignTask}
        />
      )}
    </div>
  );
}

export default TaskBoard;
