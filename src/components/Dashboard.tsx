import { useEffect, useMemo, useState } from 'react';
import type { CompanyStats, Agent, Task } from '../types';
import AgentAvatar from './AgentAvatar';

interface DashboardProps {
  stats: CompanyStats | null;
  agents: Agent[];
  tasks: Task[];
  companyName: string;
}

function useNow() {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(new Date());
    }, 30000);
    return () => window.clearInterval(timer);
  }, []);

  const date = now.toLocaleDateString('ko-KR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    weekday: 'long',
  });

  const time = now.toLocaleTimeString('ko-KR', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  const hour = now.getHours();
  const briefing = hour < 12 ? '오전 브리핑' : hour < 18 ? '오후 운영 점검' : '저녁 마감 점검';

  return { date, time, briefing };
}

function timeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}초 전`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}분 전`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}시간 전`;
  const days = Math.floor(hours / 24);
  return `${days}일 전`;
}

const STATUS_LABELS: Record<string, { label: string; color: string; dot: string }> = {
  inbox: { label: '수신함', color: 'bg-slate-500/20 text-slate-200 border-slate-400/30', dot: 'bg-slate-400' },
  planned: { label: '계획됨', color: 'bg-blue-500/20 text-blue-100 border-blue-400/30', dot: 'bg-blue-400' },
  in_progress: { label: '진행 중', color: 'bg-amber-500/20 text-amber-100 border-amber-400/30', dot: 'bg-amber-400' },
  review: { label: '검토 중', color: 'bg-violet-500/20 text-violet-100 border-violet-400/30', dot: 'bg-violet-400' },
  done: { label: '완료', color: 'bg-emerald-500/20 text-emerald-100 border-emerald-400/30', dot: 'bg-emerald-400' },
  pending: { label: '보류', color: 'bg-orange-500/20 text-orange-100 border-orange-400/30', dot: 'bg-orange-400' },
  cancelled: { label: '취소됨', color: 'bg-rose-500/20 text-rose-100 border-rose-400/30', dot: 'bg-rose-400' },
};

const RANK_ICONS = ['👑', '🥈', '🥉'];

const DEPT_COLORS = [
  { bar: 'from-blue-500 to-cyan-400', badge: 'bg-blue-500/20 text-blue-200 border-blue-400/30' },
  { bar: 'from-violet-500 to-fuchsia-400', badge: 'bg-violet-500/20 text-violet-200 border-violet-400/30' },
  { bar: 'from-emerald-500 to-teal-400', badge: 'bg-emerald-500/20 text-emerald-200 border-emerald-400/30' },
  { bar: 'from-amber-500 to-orange-400', badge: 'bg-amber-500/20 text-amber-100 border-amber-400/30' },
  { bar: 'from-rose-500 to-pink-400', badge: 'bg-rose-500/20 text-rose-100 border-rose-400/30' },
  { bar: 'from-cyan-500 to-sky-400', badge: 'bg-cyan-500/20 text-cyan-100 border-cyan-400/30' },
  { bar: 'from-orange-500 to-red-400', badge: 'bg-orange-500/20 text-orange-100 border-orange-400/30' },
  { bar: 'from-teal-500 to-lime-400', badge: 'bg-teal-500/20 text-teal-100 border-teal-400/30' },
];

function CircularProgress({ value }: { value: number }) {
  const radius = 40;
  const stroke = 6;
  const normalizedRadius = radius - stroke / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const safeValue = Math.max(0, Math.min(100, value));
  const offset = circumference - (safeValue / 100) * circumference;

  return (
    <svg height={radius * 2} width={radius * 2} className="rotate-[-90deg]">
      <circle
        stroke="#1e293b"
        fill="transparent"
        strokeWidth={stroke}
        r={normalizedRadius}
        cx={radius}
        cy={radius}
      />
      <circle
        stroke="url(#dashboardProgressGradient)"
        fill="transparent"
        strokeWidth={stroke}
        strokeDasharray={`${circumference} ${circumference}`}
        strokeDashoffset={offset}
        strokeLinecap="round"
        r={normalizedRadius}
        cx={radius}
        cy={radius}
        style={{ transition: 'stroke-dashoffset 0.6s ease' }}
      />
      <defs>
        <linearGradient id="dashboardProgressGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#22d3ee" />
          <stop offset="100%" stopColor="#3b82f6" />
        </linearGradient>
      </defs>
    </svg>
  );
}

// Cute greeting based on time of day
function getGreeting(hour: number): { emoji: string; text: string; sub: string } {
  if (hour < 6)  return { emoji: '🌙', text: '안녕히 주무세요, CEO님', sub: '늦은 밤까지 수고하셨어요 ✨' };
  if (hour < 10) return { emoji: '🌅', text: '좋은 아침이에요, CEO님!', sub: '오늘도 멋진 하루가 될 거예요 ☀️' };
  if (hour < 14) return { emoji: '☀️', text: '안녕하세요, CEO님!', sub: '에이전트들이 열심히 일하고 있어요 💪' };
  if (hour < 18) return { emoji: '🌤️', text: '오후도 화이팅이에요!', sub: '남은 업무도 잘 해낼 수 있어요 🎯' };
  if (hour < 21) return { emoji: '🌆', text: '수고하셨어요, CEO님', sub: '오늘 하루도 잘 마무리해봐요 🌸' };
  return            { emoji: '🌙', text: '오늘 하루도 고생했어요!', sub: '에이전트들도 열심히 마무리 중이에요 💫' };
}

export default function Dashboard({ stats, agents, tasks, companyName }: DashboardProps) {
  const { date, time, briefing } = useNow();
  const agentMap = useMemo(() => new Map(agents.map((agent) => [agent.id, agent])), [agents]);

  const totalTasks = stats?.tasks?.total ?? tasks.length;
  const completedTasks = stats?.tasks?.done ?? tasks.filter((t) => t.status === 'done').length;
  const inProgressTasks =
    stats?.tasks?.in_progress ?? tasks.filter((t) => t.status === 'in_progress').length;
  const plannedTasks = stats?.tasks?.planned ?? tasks.filter((t) => t.status === 'planned').length;
  const reviewTasks = stats?.tasks?.review ?? tasks.filter((t) => t.status === 'review').length;
  const pendingTasks = tasks.filter((t) => t.status === 'pending').length;
  const activeAgents =
    stats?.agents?.working ?? agents.filter((a) => a.status === 'working').length;
  const idleAgents = stats?.agents?.idle ?? agents.filter((a) => a.status === 'idle').length;
  const totalAgents = stats?.agents?.total ?? agents.length;
  const completionRate =
    stats?.tasks?.completion_rate ??
    (totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0);
  const activeRate = totalAgents > 0 ? Math.round((activeAgents / totalAgents) * 100) : 0;
  const reviewQueue = reviewTasks + pendingTasks;

  const deptData = useMemo(() => {
    if (stats?.tasks_by_department && stats.tasks_by_department.length > 0) {
      return stats.tasks_by_department
        .map((d, i) => ({
          id: d.id,
          name: d.name,
          icon: d.icon ?? '🏢',
          done: d.done_tasks,
          total: d.total_tasks,
          ratio: d.total_tasks > 0 ? Math.round((d.done_tasks / d.total_tasks) * 100) : 0,
          color: DEPT_COLORS[i % DEPT_COLORS.length],
        }))
        .sort((a, b) => b.ratio - a.ratio || b.total - a.total);
    }

    const deptMap = new Map<string, { name: string; icon: string; done: number; total: number }>();
    for (const agent of agents) {
      if (!agent.department_id) continue;
      if (!deptMap.has(agent.department_id)) {
        deptMap.set(agent.department_id, {
          name: agent.department?.name_ko ?? agent.department?.name ?? agent.department_id,
          icon: agent.department?.icon ?? '🏢',
          done: 0,
          total: 0,
        });
      }
    }

    for (const task of tasks) {
      if (!task.department_id) continue;
      const entry = deptMap.get(task.department_id);
      if (!entry) continue;
      entry.total += 1;
      if (task.status === 'done') entry.done += 1;
    }

    return Array.from(deptMap.entries())
      .map(([id, value], i) => ({
        id,
        ...value,
        ratio: value.total > 0 ? Math.round((value.done / value.total) * 100) : 0,
        color: DEPT_COLORS[i % DEPT_COLORS.length],
      }))
      .sort((a, b) => b.ratio - a.ratio || b.total - a.total);
  }, [stats, agents, tasks]);

  const topAgents = useMemo(() => {
    if (stats?.top_agents && stats.top_agents.length > 0) {
      return stats.top_agents.slice(0, 5).map((topAgent) => {
        const agent = agentMap.get(topAgent.id);
        return {
          id: topAgent.id,
          name: agent?.name_ko ?? agent?.name ?? topAgent.name,
          department: agent?.department?.name_ko ?? agent?.department?.name ?? '',
          tasksDone: topAgent.stats_tasks_done,
          xp: topAgent.stats_xp,
        };
      });
    }

    return [...agents]
      .sort((a, b) => b.stats_xp - a.stats_xp)
      .slice(0, 5)
      .map((agent) => ({
        id: agent.id,
        name: agent.name_ko ?? agent.name,
        department: agent.department?.name_ko ?? agent.department?.name ?? '',
        tasksDone: agent.stats_tasks_done,
        xp: agent.stats_xp,
      }));
  }, [stats, agents, agentMap]);

  const maxXp = topAgents.length > 0 ? Math.max(...topAgents.map((agent) => agent.xp), 1) : 1;

  const recentTasks = useMemo(
    () =>
      [...tasks]
        .sort((a, b) => b.updated_at - a.updated_at)
        .slice(0, 6),
    [tasks]
  );

  const kpiCards = [
    {
      id: 'total',
      label: '전체 업무',
      value: totalTasks.toLocaleString('ko-KR'),
      sub: '누적 등록 태스크',
      icon: '📋',
      gradient: 'from-blue-600/30 via-blue-500/15 to-transparent',
      accent: 'from-blue-400 to-cyan-400',
      border: 'border-blue-400/25 hover:border-blue-400/50',
      glow: 'hover:shadow-blue-500/20',
      valueTone: 'text-blue-100',
      delay: '0ms',
    },
    {
      id: 'done',
      label: '완료율',
      value: `${completionRate}%`,
      sub: `${completedTasks.toLocaleString('ko-KR')}건 완료`,
      icon: '✅',
      gradient: 'from-emerald-600/30 via-emerald-500/15 to-transparent',
      accent: 'from-emerald-400 to-teal-400',
      border: 'border-emerald-400/25 hover:border-emerald-400/50',
      glow: 'hover:shadow-emerald-500/20',
      valueTone: 'text-emerald-200',
      delay: '60ms',
    },
    {
      id: 'active',
      label: '활동 에이전트',
      value: `${activeAgents}/${totalAgents}`,
      sub: `가동률 ${activeRate}%`,
      icon: '🤖',
      gradient: 'from-cyan-600/30 via-cyan-500/15 to-transparent',
      accent: 'from-cyan-400 to-sky-400',
      border: 'border-cyan-400/25 hover:border-cyan-400/50',
      glow: 'hover:shadow-cyan-500/20',
      valueTone: 'text-cyan-200',
      delay: '120ms',
    },
    {
      id: 'progress',
      label: '진행 중 업무',
      value: inProgressTasks.toLocaleString('ko-KR'),
      sub: `계획 ${plannedTasks.toLocaleString('ko-KR')}건`,
      icon: '⚡',
      gradient: 'from-amber-600/30 via-amber-500/15 to-transparent',
      accent: 'from-amber-400 to-orange-400',
      border: 'border-amber-400/25 hover:border-amber-400/50',
      glow: 'hover:shadow-amber-500/20',
      valueTone: 'text-amber-200',
      delay: '180ms',
    },
  ];

  const now = new Date();
  const greeting = getGreeting(now.getHours());

  // Separate agents into working and idle for the bubble grid
  const workingAgents = agents.filter((a) => a.status === 'working');
  const idleAgentsList = agents.filter((a) => a.status === 'idle');

  // Podium: top 3 agents reordered as [2nd, 1st, 3rd] for visual podium effect
  const podiumOrder =
    topAgents.length >= 3
      ? [topAgents[1], topAgents[0], topAgents[2]]
      : topAgents.length === 2
      ? [topAgents[1], topAgents[0]]
      : topAgents;

  const podiumHeights = ['h-20', 'h-28', 'h-14'];
  const podiumRanks  = [2, 1, 3];

  const STATUS_LEFT_BORDER: Record<string, string> = {
    inbox:       'border-l-slate-400',
    planned:     'border-l-blue-400',
    in_progress: 'border-l-amber-400',
    review:      'border-l-violet-400',
    done:        'border-l-emerald-400',
    pending:     'border-l-orange-400',
    cancelled:   'border-l-rose-400',
  };

  return (
    <section className="relative isolate space-y-5 text-slate-100">

      {/* Ambient blobs */}
      <div className="pointer-events-none absolute -left-32 -top-24 h-80 w-80 rounded-full bg-pink-500/8 blur-3xl" />
      <div className="pointer-events-none absolute -right-20 top-10 h-72 w-72 rounded-full bg-cyan-500/8 blur-3xl" />
      <div className="pointer-events-none absolute left-1/2 bottom-40 h-64 w-64 -translate-x-1/2 rounded-full bg-violet-500/6 blur-3xl" />

      {/* ─── GREETING HEADER ─── */}
      <div className="relative overflow-hidden rounded-3xl border border-white/8 bg-gradient-to-br from-slate-800/80 via-slate-900/90 to-slate-950/95 p-6 shadow-2xl shadow-slate-950/60 backdrop-blur-sm sm:p-8">

        {/* Decorative top-right corner blob */}
        <div className="pointer-events-none absolute -right-10 -top-10 h-48 w-48 rounded-full bg-gradient-to-br from-pink-400/12 to-violet-400/8 blur-2xl" />
        <div className="pointer-events-none absolute bottom-0 left-0 h-32 w-64 rounded-full bg-cyan-400/6 blur-2xl" />

        {/* Decorative dots pattern */}
        <div className="pointer-events-none absolute right-6 top-6 opacity-20" aria-hidden>
          {[0,1,2].map((row) =>
            [0,1,2,3].map((col) => (
              <div
                key={`${row}-${col}`}
                className="absolute h-1 w-1 rounded-full bg-white"
                style={{ top: row * 12, left: col * 12 }}
              />
            ))
          )}
        </div>

        <div className="relative grid gap-6 xl:grid-cols-[1.4fr_1fr]">
          {/* Left: greeting */}
          <div className="space-y-3 animate-greeting">
            <div className="flex items-center gap-3">
              <span
                className="text-4xl animate-heart-beat"
                style={{ display: 'inline-block' }}
              >
                {greeting.emoji}
              </span>
              <div>
                <h1 className="text-xl font-bold leading-tight text-white sm:text-2xl">
                  {greeting.text}
                </h1>
                <p className="mt-0.5 text-sm text-slate-400">{greeting.sub}</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-2xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 via-blue-300 to-violet-300 sm:text-3xl">
                {companyName}
              </h2>
            </div>

            <p className="max-w-lg text-sm leading-relaxed text-slate-400">
              실시간 진행 현황을 한 화면에서 확인하고 우선순위를 빠르게 조정할 수 있어요 🗂️
            </p>

            <div className="flex flex-wrap gap-2 pt-1">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-400/30 bg-emerald-500/12 px-3 py-1 text-xs font-medium text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                {date}
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-400/25 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-300">
                ⏰ {briefing}
              </span>
              {reviewQueue > 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-orange-400/25 bg-orange-500/10 px-3 py-1 text-xs font-medium text-orange-300">
                  🔔 검토 대기 {reviewQueue.toLocaleString('ko-KR')}건
                </span>
              )}
            </div>
          </div>

          {/* Right: clock + completion */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
            {/* Clock pill */}
            <div className="relative overflow-hidden rounded-2xl border border-white/8 bg-gradient-to-br from-slate-800/60 to-slate-900/80 px-5 py-4 shadow-inner shadow-slate-950/40">
              <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-cyan-400/5 to-transparent" />
              <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">현재 시각</p>
              <p className="mt-1.5 font-mono text-3xl font-bold tracking-tight text-cyan-200">{time}</p>
              <p className="mt-1 text-[11px] text-slate-500">30초마다 자동 갱신</p>
              <div className="absolute right-4 top-1/2 -translate-y-1/2 text-3xl opacity-15">🕐</div>
            </div>

            {/* Completion ring */}
            <div className="relative overflow-hidden rounded-2xl border border-white/8 bg-gradient-to-br from-slate-800/60 to-slate-900/80 p-4 shadow-inner shadow-slate-950/40">
              <div className="flex items-center gap-4">
                <div className="relative grid h-20 w-20 flex-shrink-0 place-items-center">
                  <CircularProgress value={completionRate} />
                  <span className="absolute text-sm font-bold text-cyan-200">{completionRate}%</span>
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-slate-100">업무 완료율</p>
                  <p className="mt-1 text-[11px] text-slate-400">
                    {completedTasks.toLocaleString('ko-KR')}건 / {totalTasks.toLocaleString('ko-KR')}건
                  </p>
                  <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-700/60">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-blue-400 transition-all duration-700"
                      style={{ width: `${completionRate}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ─── KPI CARDS ─── */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {kpiCards.map((card) => (
          <div
            key={card.id}
            className={`group relative cursor-default overflow-hidden rounded-3xl border bg-slate-900/70 p-5 shadow-lg transition-all duration-300 hover:-translate-y-1 hover:shadow-xl ${card.border} ${card.glow}`}
            style={{ animationDelay: card.delay }}
          >
            {/* Gradient wash */}
            <div className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${card.gradient}`} />

            {/* Icon bubble */}
            <div className="relative mb-4 flex items-start justify-between">
              <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-white/10 bg-white/8 text-2xl shadow-inner shadow-black/20 transition-transform duration-300 group-hover:scale-110">
                {card.icon}
              </span>
              {/* Accent bar top-right */}
              <div className={`h-1 w-10 rounded-full bg-gradient-to-r ${card.accent} opacity-60`} />
            </div>

            <div className="relative">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{card.label}</p>
              <p className={`mt-1.5 text-3xl font-extrabold tracking-tight transition-transform duration-200 group-hover:scale-105 ${card.valueTone}`}>
                {card.value}
              </p>
              <p className="mt-1 text-[11px] text-slate-500">{card.sub}</p>
            </div>

            {/* Bottom accent line */}
            <div className={`absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r ${card.accent} opacity-0 transition-opacity duration-300 group-hover:opacity-40`} />
          </div>
        ))}
      </div>

      {/* ─── AGENT STATUS BUBBLES ─── */}
      {agents.length > 0 && (
        <div className="rounded-3xl border border-white/8 bg-slate-900/60 p-5 shadow-lg">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-white">
              <span className="flex h-7 w-7 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/30 to-blue-500/20 text-sm">
                🤖
              </span>
              에이전트 현황
            </h2>
            <div className="flex items-center gap-2 text-xs">
              <span className="flex items-center gap-1 rounded-full border border-emerald-400/25 bg-emerald-500/10 px-2.5 py-0.5 font-medium text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                작업 중 {workingAgents.length}명
              </span>
              <span className="flex items-center gap-1 rounded-full border border-slate-600/40 bg-slate-700/30 px-2.5 py-0.5 font-medium text-slate-400">
                대기 {idleAgentsList.length}명
              </span>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            {agents.map((agent) => {
              const isWorking = agent.status === 'working';
              return (
                <div
                  key={agent.id}
                  title={`${agent.name_ko ?? agent.name} — ${isWorking ? '작업 중' : '대기 중'}`}
                  className={`group relative flex flex-col items-center gap-1.5 ${isWorking ? 'animate-bubble-float' : ''}`}
                  style={isWorking ? { animationDelay: `${Math.random() * 1500}ms` } : {}}
                >
                  {/* Avatar with status ring */}
                  <div className="relative">
                    <div
                      className={`rounded-2xl overflow-hidden transition-transform duration-200 group-hover:scale-110 ${
                        isWorking
                          ? 'ring-2 ring-emerald-400/70 ring-offset-1 ring-offset-slate-900 shadow-lg shadow-emerald-500/20'
                          : 'ring-1 ring-slate-600/50 ring-offset-1 ring-offset-slate-900'
                      }`}
                    >
                      <AgentAvatar agent={agent} agents={agents} size={40} rounded="2xl" />
                    </div>
                    {/* Status dot */}
                    <span
                      className={`absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-slate-900 ${
                        isWorking ? 'bg-emerald-400 animate-status-glow' : 'bg-slate-500'
                      }`}
                    />
                  </div>
                  {/* Name label */}
                  <span className={`max-w-[52px] truncate text-center text-[9px] font-medium leading-tight ${
                    isWorking ? 'text-emerald-300' : 'text-slate-500'
                  }`}>
                    {agent.name_ko ?? agent.name}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ─── DEPARTMENT + LEADERBOARD ─── */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1.2fr_1fr]">

        {/* Department progress */}
        <div className="rounded-3xl border border-white/8 bg-slate-900/60 p-5 shadow-lg">
          <h2 className="mb-4 flex items-center gap-2 text-base font-bold text-white">
            <span className="flex h-7 w-7 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500/30 to-cyan-500/20 text-sm">
              🏗️
            </span>
            부서별 성과
          </h2>

          {deptData.length === 0 ? (
            <div className="flex min-h-[280px] flex-col items-center justify-center gap-2 text-sm text-slate-500">
              <span className="text-3xl opacity-40">📊</span>
              데이터가 없습니다
            </div>
          ) : (
            <div className="space-y-3">
              {deptData.map((dept, idx) => (
                <article
                  key={dept.id}
                  className="group relative overflow-hidden rounded-2xl border border-white/6 bg-slate-800/40 p-3.5 transition-all duration-200 hover:-translate-y-0.5 hover:border-white/12 hover:bg-slate-800/60 hover:shadow-md"
                  style={{ animationDelay: `${idx * 40}ms` }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-xl border border-white/10 bg-slate-700/60 text-base transition-transform duration-200 group-hover:scale-110">
                        {dept.icon}
                      </span>
                      <span className="text-sm font-semibold text-slate-100">{dept.name}</span>
                    </div>
                    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-bold ${dept.color.badge}`}>
                      {dept.ratio}%
                    </span>
                  </div>

                  <div className="mt-2.5 h-2 overflow-hidden rounded-full bg-slate-700/50">
                    <div
                      className={`relative h-full rounded-full bg-gradient-to-r ${dept.color.bar} transition-all duration-700`}
                      style={{ width: `${dept.ratio}%` }}
                    >
                      <div className="absolute inset-0 animate-[shimmer_2.4s_linear_infinite] bg-gradient-to-r from-white/0 via-white/25 to-white/0" />
                    </div>
                  </div>

                  <div className="mt-1.5 flex justify-between text-[10px] font-medium uppercase tracking-wider text-slate-500">
                    <span>완료 {dept.done.toLocaleString('ko-KR')}건</span>
                    <span>전체 {dept.total.toLocaleString('ko-KR')}건</span>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        {/* Leaderboard — podium top 3 + list 4-5 */}
        <div className="rounded-3xl border border-white/8 bg-slate-900/60 p-5 shadow-lg">
          <h2 className="mb-4 flex items-center gap-2 text-base font-bold text-white">
            <span className="flex h-7 w-7 items-center justify-center rounded-xl bg-gradient-to-br from-amber-500/30 to-orange-500/20 text-sm animate-crown-wiggle">
              🏆
            </span>
            에이전트 리더보드
          </h2>

          {topAgents.length === 0 ? (
            <div className="flex min-h-[280px] flex-col items-center justify-center gap-2 text-sm text-slate-500">
              <span className="text-3xl opacity-40">🤷</span>
              등록된 에이전트가 없습니다
            </div>
          ) : (
            <div className="space-y-4">

              {/* Podium visual for top 3 */}
              {topAgents.length >= 2 && (
                <div className="flex items-end justify-center gap-3 pb-2 pt-1">
                  {podiumOrder.map((agent, visualIdx) => {
                    const rank = podiumRanks[visualIdx];
                    const isFirst = rank === 1;
                    const podiumH = podiumHeights[visualIdx];
                    const podiumBg = isFirst
                      ? 'from-amber-500/40 to-yellow-600/20 border-amber-400/40'
                      : rank === 2
                      ? 'from-slate-400/30 to-slate-500/20 border-slate-400/30'
                      : 'from-orange-600/30 to-orange-700/20 border-orange-500/30';

                    return (
                      <div key={agent.id} className="flex flex-col items-center gap-1.5">
                        {/* Crown / medal above avatar */}
                        {rank === 1 && (
                          <span className="text-lg animate-crown-wiggle" style={{ display: 'inline-block' }}>
                            👑
                          </span>
                        )}
                        {rank === 2 && <span className="text-base opacity-80">🥈</span>}
                        {rank === 3 && <span className="text-base opacity-80">🥉</span>}

                        {/* Avatar */}
                        <div className={`rounded-2xl overflow-hidden flex-shrink-0 ${
                          isFirst
                            ? 'ring-2 ring-amber-400/70 ring-offset-1 ring-offset-slate-900 shadow-lg shadow-amber-500/25'
                            : 'ring-1 ring-white/10'
                        }`}>
                          <AgentAvatar agent={agentMap.get(agent.id)} agents={agents} size={isFirst ? 52 : 40} rounded="2xl" />
                        </div>

                        {/* Name */}
                        <span className={`max-w-[70px] truncate text-center text-[10px] font-bold ${
                          isFirst ? 'text-amber-200' : 'text-slate-300'
                        }`}>
                          {agent.name}
                        </span>

                        {/* XP chip */}
                        <span className={`rounded-full px-2 py-0.5 text-[9px] font-semibold ${
                          isFirst
                            ? 'bg-amber-500/20 text-amber-200 border border-amber-400/30'
                            : 'bg-slate-700/60 text-slate-400 border border-white/8'
                        }`}>
                          {agent.xp.toLocaleString()} XP
                        </span>

                        {/* Podium block */}
                        <div className={`w-20 rounded-t-2xl border bg-gradient-to-b ${podiumBg} ${podiumH} flex items-center justify-center`}>
                          <span className="text-xl font-black text-white/40">#{rank}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Ranks 4-5 as compact rows */}
              {topAgents.length > 3 && (
                <div className="space-y-2 border-t border-white/8 pt-3">
                  {topAgents.slice(3).map((agent, idx) => (
                    <div
                      key={agent.id}
                      className="flex items-center gap-3 rounded-2xl border border-white/6 bg-slate-800/40 p-2.5 transition-all hover:border-white/12 hover:bg-slate-800/60"
                    >
                      <span className="w-5 text-center font-mono text-xs font-bold text-slate-500">
                        #{idx + 4}
                      </span>
                      <AgentAvatar agent={agentMap.get(agent.id)} agents={agents} size={32} rounded="xl" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-semibold text-slate-200">{agent.name}</p>
                        <p className="text-[10px] text-slate-500">{agent.department || '미지정'}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-[10px] font-bold text-blue-300">{agent.xp.toLocaleString()} XP</p>
                        <p className="text-[9px] text-slate-500">{agent.tasksDone} 완료</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* If only 1 agent, show as single compact card */}
              {topAgents.length === 1 && (
                <div className="flex items-center gap-3 rounded-2xl border border-amber-400/30 bg-gradient-to-r from-amber-600/20 to-orange-500/10 p-3.5">
                  <span className="text-xl animate-crown-wiggle" style={{ display: 'inline-block' }}>👑</span>
                  <AgentAvatar agent={agentMap.get(topAgents[0].id)} agents={agents} size={44} rounded="2xl" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-bold text-amber-100">{topAgents[0].name}</p>
                    <p className="text-xs text-amber-300/70">{topAgents[0].department || '미지정'}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-bold text-amber-200">{topAgents[0].xp.toLocaleString()} XP</p>
                    <p className="text-[10px] text-amber-300/60">{topAgents[0].tasksDone} 완료</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ─── RECENT ACTIVITY ─── */}
      <div className="rounded-3xl border border-white/8 bg-slate-900/60 p-5 shadow-lg">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-base font-bold text-white">
            <span className="flex h-7 w-7 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/30 to-blue-500/20 text-sm">
              📡
            </span>
            최근 활동
          </h2>
          <span className="flex items-center gap-1.5 rounded-full border border-slate-600/40 bg-slate-700/30 px-2.5 py-0.5 text-[11px] font-medium text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
            유휴 에이전트 {idleAgents.toLocaleString('ko-KR')}명
          </span>
        </div>

        {recentTasks.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-12 text-sm text-slate-500">
            <span className="text-3xl opacity-40">🌿</span>
            최근 활동 없음
          </div>
        ) : (
          <div className="space-y-2">
            {recentTasks.map((task) => {
              const statusInfo = STATUS_LABELS[task.status] ?? {
                label: task.status,
                color: 'bg-slate-600/20 text-slate-200 border-slate-500/30',
                dot: 'bg-slate-400',
              };
              const assignedAgent =
                task.assigned_agent ??
                (task.assigned_agent_id ? agentMap.get(task.assigned_agent_id) : undefined);
              const leftBorder = STATUS_LEFT_BORDER[task.status] ?? 'border-l-slate-500';

              return (
                <article
                  key={task.id}
                  className={`grid grid-cols-[auto_1fr_auto] items-center gap-3 rounded-2xl border border-white/6 border-l-2 ${leftBorder} bg-slate-800/35 p-3 transition-all duration-200 hover:scale-[1.01] hover:border-white/12 hover:bg-slate-800/60 hover:shadow-md`}
                >
                  {assignedAgent ? (
                    <AgentAvatar agent={assignedAgent} agents={agents} size={38} rounded="xl" />
                  ) : (
                    <div className="flex h-[38px] w-[38px] flex-shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-800 text-lg text-slate-400">
                      📄
                    </div>
                  )}

                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-slate-100">{task.title}</p>
                    <p className="mt-0.5 flex items-center gap-1.5 text-[11px] text-slate-400">
                      <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${statusInfo.dot}`} />
                      {assignedAgent ? (assignedAgent.name_ko ?? assignedAgent.name) : '미배정'}
                    </p>
                  </div>

                  <div className="flex flex-col items-end gap-1">
                    <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${statusInfo.color}`}>
                      {statusInfo.label}
                    </span>
                    <span className="text-[10px] text-slate-500">{timeAgo(task.updated_at)}</span>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
