<p align="center">
  <img src="public/claw-empire.svg" width="80" alt="Claw-Empire" />
</p>

<h1 align="center">Claw-Empire</h1>

<p align="center">
  <strong>CEO 데스크에서 AI 에이전트 제국을 지휘하세요</strong><br>
  <b>Claude Code</b>, <b>Codex CLI</b>, <b>Gemini CLI</b>, <b>OpenCode</b>, <b>GitHub Copilot</b>, <b>Antigravity</b>를 자율 에이전트 가상 회사로 변환하는 로컬 퍼스트 AI 에이전트 오피스 시뮬레이터
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.5-blue" alt="Version" />
  <img src="https://img.shields.io/badge/node-%3E%3D22-brightgreen" alt="Node.js 22+" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-orange" alt="License" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Platform" />
  <img src="https://img.shields.io/badge/AI-Claude%20%7C%20Codex%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Copilot%20%7C%20Antigravity-purple" alt="AI Agents" />
</p>

<p align="center">
  <a href="#빠른-시작">빠른 시작</a> &middot;
  <a href="#ai-installation-guide">AI 설치 가이드</a> &middot;
  <a href="docs/releases/v1.0.5.md">릴리즈 노트</a> &middot;
  <a href="#openclaw-integration">OpenClaw 연동</a> &middot;
  <a href="#dollar-command-logic">$ 명령 로직</a> &middot;
  <a href="#주요-기능">주요 기능</a> &middot;
  <a href="#스크린샷">스크린샷</a> &middot;
  <a href="#기술-스택">기술 스택</a> &middot;
  <a href="#cli-프로바이더-설정">프로바이더</a> &middot;
  <a href="#보안">보안</a>
</p>

<p align="center">
  <a href="README.md">English</a> | <b>한국어</b> | <a href="README_jp.md">日本語</a> | <a href="README_zh.md">中文</a>
</p>

<p align="center">
  <img src="Sample_Img/Office.png" alt="Office View" width="100%" />
</p>

---

## Claw-Empire란?

Claw-Empire는 CLI 기반 AI 코딩 어시스턴트 — **Claude Code**, **Codex CLI**, **Gemini CLI**, **OpenCode** 등 — 를 완전한 **가상 소프트웨어 회사**로 탈바꿈시킵니다. 당신은 CEO입니다. AI 에이전트들은 당신의 직원입니다. 에이전트들이 부서 간 협업하고, 회의를 열고, 업무를 완수하며, 레벨업하는 모습을 아기자기한 픽셀 아트 오피스 화면으로 직접 확인하세요.

### 왜 Claw-Empire인가?

- **하나의 인터페이스, 다양한 AI 에이전트** — Claude Code, Codex, Gemini CLI 등을 단일 대시보드에서 관리
- **로컬 퍼스트 & 프라이버시 보장** — 모든 데이터는 내 PC에. SQLite 데이터베이스, 클라우드 의존성 없음
- **시각적이고 직관적** — 픽셀 아트 오피스 뷰가 AI 오케스트레이션을 즐겁고 투명하게 만들어줌
- **진정한 자율 협업** — 에이전트들이 독립된 git worktree에서 작업하고, 회의에 참석하며, 결과물을 생산

---

## 최신 릴리즈 (v1.0.5)

- 서버 런타임 흐름을 추가 모듈화하여 라우트/워크플로우/런타임 결합부 유지보수성을 강화
- 런타임 언어 정합성 강화: 업무 실행 프롬프트와 워크플로우/상태 메시지가 선택 언어를 일관되게 따르도록 개선
- `/api/inbox` 연동 문서를 통일: `x-inbox-secret` 헤더는 필수이며 누락/불일치 시 `401` 반환
- AI 설치 가이드와 빠른 시작에 `INBOX_WEBHOOK_SECRET`, `OPENCLAW_CONFIG` 검증 절차를 명시
- `OPENCLAW_CONFIG` 처리 보강: 런타임에서 따옴표/선행 `~` 값을 정규화
- OpenClaw 설정 문서에 `.env` 절대경로(따옴표 없이 권장) 규칙을 명확히 반영
- 기존 클론 사용자가 `v1.0.5`를 `git pull`만 한 경우에도 첫 `pnpm dev*` / `pnpm start*` 실행 시 1회 자동 마이그레이션 적용
- AGENTS 오케스트레이션에 `INBOX_SECRET_DISCOVERY_V2`를 추가해 쉘 env, `.env`, `.env.clone`, 공통 프로젝트 루트에서 시크릿 자동 탐색 지원
- 에이전트 1:1 채팅에서 장문 응답 잘림을 보완하고, 동일 문구 반복 출력 사이클을 축소
- 상세 문서: [`docs/releases/v1.0.5.md`](docs/releases/v1.0.5.md)

---

## AI로 설치하기

> **아래 내용을 AI 코딩 에이전트(Claude Code, Codex, Gemini CLI 등)에 붙여넣기만 하세요:**
>
> ```
> Install Claw-Empire following the guide at:
> https://github.com/GreenSheep01201/claw-empire
> ```
>
> AI가 이 README를 읽고 모든 것을 자동으로 처리합니다.

---

## 스크린샷

<table>
<tr>
<td width="50%">

**대시보드** — 실시간 KPI 지표, 에이전트 랭킹, 부서 현황을 한눈에

<img src="Sample_Img/Dashboard.png" alt="Dashboard" width="100%" />
</td>
<td width="50%">

**칸반 보드** — 부서 및 에이전트 필터가 적용된 드래그 앤 드롭 태스크 관리

<img src="Sample_Img/Kanban.png" alt="Kanban Board" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**스킬 라이브러리** — 카테고리별로 분류된 600개 이상의 에이전트 스킬 탐색 및 배정

<img src="Sample_Img/Skills.png" alt="Skills Library" width="100%" />
</td>
<td width="50%">

**멀티 프로바이더 CLI** — Claude Code, Codex, Gemini CLI, OpenCode를 모델 선택과 함께 설정

<img src="Sample_Img/CLI.png" alt="CLI Tools Settings" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**OAuth 연동** — 암호화된 토큰 저장소가 적용된 안전한 GitHub & Google OAuth

<img src="Sample_Img/OAuth.png" alt="OAuth Settings" width="100%" />
</td>
<td width="50%">

**회의록** — 다중 라운드 검토 승인이 포함된 AI 생성 회의 요약

<img src="Sample_Img/Meeting_Minutes.png" alt="Meeting Minutes" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**메신저 연동** — Telegram, Discord, Slack에서 `$` CEO 디렉티브를 전송하고 실시간 태스크 업데이트를 수신 (OpenClaw 연동)

<img src="Sample_Img/telegram.png" alt="Messenger Integration" width="100%" />
</td>
<td width="50%">

**설정** — 회사명, CEO 이름, 기본 CLI 프로바이더, 언어 등 환경 설정

<img src="Sample_Img/Setting.png" alt="Settings" width="100%" />
</td>
</tr>
</table>

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **픽셀 아트 오피스** | 6개 부서에 걸쳐 에이전트들이 이동, 업무, 회의를 진행하는 애니메이션 오피스 뷰 |
| **칸반 태스크 보드** | Inbox, Planned, Collaborating, In Progress, Review, Done — 드래그 앤 드롭이 가능한 완전한 태스크 생애주기 관리 |
| **CEO 채팅 & 디렉티브** | 팀 리더와의 직접 소통; `$` 디렉티브에서 회의 여부와 작업 경로/컨텍스트(`project_path`, `project_context`) 기반 지시 지원 |
| **멀티 프로바이더 지원** | Claude Code, Codex CLI, Gemini CLI, OpenCode, Antigravity — 하나의 대시보드에서 모두 관리 |
| **OAuth 연동** | 로컬 SQLite에 AES 암호화된 토큰 저장을 사용하는 GitHub & Google OAuth |
| **실시간 WebSocket** | 실시간 상태 업데이트, 활동 피드, 에이전트 상태 동기화 |
| **에이전트 랭킹 & XP** | 완료된 태스크로 XP를 획득하는 에이전트; 랭킹 보드에서 상위 성과자 추적 |
| **스킬 라이브러리** | 카테고리별로 정리된 600개 이상의 스킬 (Frontend, Backend, Design, AI, DevOps, Security 등) |
| **회의 시스템** | AI 생성 회의록과 다중 라운드 검토가 포함된 계획 및 임시 회의 |
| **Git Worktree 격리** | 각 에이전트는 독립된 git 브랜치에서 작업하며 CEO 승인 시에만 병합 |
| **다국어 UI** | 한국어, 영어, 일본어, 중국어 — 자동 감지 또는 수동 설정 |
| **메신저 연동** | Telegram, Discord, Slack 등 — OpenClaw 게이트웨이를 통해 `$` CEO 디렉티브 전송 및 태스크 업데이트 수신 |
| **PowerPoint 내보내기** | 회의록과 보고서로부터 프레젠테이션 슬라이드 생성 |
| **부서 관리** | 기획, 개발, 디자인, QA/QC, DevSecOps, 운영 |

---

## 기술 스택

| 레이어 | 기술 |
|--------|------|
| **Frontend** | React 19 + Vite 7 + Tailwind CSS 4 + TypeScript 5.9 |
| **픽셀 아트 엔진** | PixiJS 8 |
| **Backend** | Express 5 + SQLite (설정 없는 내장 DB) |
| **실시간 통신** | WebSocket (ws) |
| **유효성 검사** | Zod 4 |
| **아이콘** | Lucide React |
| **라우팅** | React Router 7 |
| **내보내기** | PptxGenJS (PowerPoint 생성) |

<a id="ai-installation-guide">
## AI 설치 가이드

> 이 섹션은 AI 코딩 에이전트용입니다. 각 단계마다 검증 명령을 실행한 후 다음 단계로 진행하세요.

### 0단계: 사전 조건 확인

```bash
# Node.js 22+
node -v

# pnpm (없다면 corepack 활성화)
pnpm -v || corepack enable

# git
git --version
```

### 1단계: 클론 후 원클릭 셋업 실행

```bash
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire
bash install.sh
```

Windows PowerShell:

```powershell
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### 2단계: 셋업 결과 검증

macOS/Linux:

```bash
# 필수 파일 확인
[ -f .env ] && [ -f scripts/setup.mjs ] && echo "setup files ok"

# AGENTS 오케스트레이션 규칙 확인
grep -R "BEGIN claw-empire orchestration rules" ~/.openclaw/workspace/AGENTS.md AGENTS.md 2>/dev/null || true
grep -R "INBOX_SECRET_DISCOVERY_V2" ~/.openclaw/workspace/AGENTS.md AGENTS.md 2>/dev/null || true

# OpenClaw inbox 필수 .env 항목 확인
grep -E '^(INBOX_WEBHOOK_SECRET|OPENCLAW_CONFIG)=' .env || true
```

Windows PowerShell:

```powershell
if ((Test-Path .\.env) -and (Test-Path .\scripts\setup.mjs)) { "setup files ok" }
$agentCandidates = @("$env:USERPROFILE\.openclaw\workspace\AGENTS.md", ".\AGENTS.md")
$agentCandidates | ForEach-Object { if (Test-Path $_) { Select-String -Path $_ -Pattern "BEGIN claw-empire orchestration rules" } }
$agentCandidates | ForEach-Object { if (Test-Path $_) { Select-String -Path $_ -Pattern "INBOX_SECRET_DISCOVERY_V2" } }

# OpenClaw inbox 필수 .env 항목 확인
Get-Content .\.env | Select-String -Pattern '^(INBOX_WEBHOOK_SECRET|OPENCLAW_CONFIG)='
```

### 3단계: 실행 및 헬스체크

```bash
pnpm dev:local
```

다른 터미널에서:

```bash
curl -s http://127.0.0.1:8790/healthz
```

예상 응답: `{"ok":true,...}`

`.env`의 `OPENCLAW_CONFIG`는 절대경로 사용을 권장합니다(문서 기준 따옴표 없이 권장). `v1.0.5`에서는 따옴표/선행 `~` 값도 런타임에서 정규화합니다.

### 4단계: OpenClaw 게이트웨이 + inbox(선택) 검증

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

`OPENCLAW_CONFIG`가 올바르면 사용 가능한 메신저 세션 목록이 반환됩니다.

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -H "x-inbox-secret: $INBOX_WEBHOOK_SECRET" \
  -d '{"source":"telegram","author":"ceo","text":"$README v1.0.5 inbox 점검","skipPlannedMeeting":true}'
```

예상 응답:
- 서버에 `INBOX_WEBHOOK_SECRET`이 설정되어 있고 `x-inbox-secret`이 일치하면 `200`
- 헤더 누락/불일치 시 `401`
- 서버에 `INBOX_WEBHOOK_SECRET`이 미설정이면 `503`

---

## 빠른 시작

### 사전 요구사항

| 도구 | 버전 | 설치 |
|------|------|------|
| **Node.js** | >= 22 | [nodejs.org](https://nodejs.org/) |
| **pnpm** | 최신 | `corepack enable` (Node.js에 내장) |
| **Git** | 무관 | [git-scm.com](https://git-scm.com/) |

### 원클릭 셋업 (권장)

| 플랫폼 | 명령어 |
|--------|--------|
| **macOS / Linux** | `git clone https://github.com/GreenSheep01201/claw-empire.git && cd claw-empire && bash install.sh` |
| **Windows (PowerShell)** | `git clone https://github.com/GreenSheep01201/claw-empire.git; cd claw-empire; powershell -ExecutionPolicy Bypass -File .\install.ps1` |

이미 클론되어 있다면:

| 플랫폼 | 명령어 |
|--------|--------|
| **macOS / Linux** | `bash scripts/openclaw-setup.sh` |
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1` |

### OpenClaw `.env` 필수값 (`/api/inbox` 사용 시)

채팅 웹훅 연동 전 `.env`에 아래 두 값을 설정하세요.

- `INBOX_WEBHOOK_SECRET=<충분히 긴 랜덤 시크릿>`
- `OPENCLAW_CONFIG=<openclaw.json 절대경로>` (따옴표 없이 권장)

`scripts/openclaw-setup.sh` / `scripts/openclaw-setup.ps1`는 `INBOX_WEBHOOK_SECRET`이 비어 있으면 자동 생성합니다.
초기 설치(`bash install.sh` / `install.ps1`)도 동일 셋업 스크립트를 거치므로 처음부터 자동 반영됩니다.
이미 클론된 저장소에서 `git pull`만 한 경우에도 `pnpm dev*` / `pnpm start*` 최초 실행 시 필요 조건에서 1회 자동 보정되며, 이후 반복 실행을 막기 위해 `CLAW_MIGRATION_V1_0_5_DONE=1`이 저장됩니다.

`/api/inbox`는 서버 측 `INBOX_WEBHOOK_SECRET` 설정과 `x-inbox-secret` 헤더의 정확한 일치가 필요합니다.
- 헤더 누락/불일치 -> `401`
- 서버 설정 누락(`INBOX_WEBHOOK_SECRET`) -> `503`

### 수동 셋업 (대체 경로)

<details>
<summary><b>macOS / Linux</b></summary>

```bash
# 1. 저장소 클론
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. corepack으로 pnpm 활성화
corepack enable

# 3. 의존성 설치
pnpm install

# 4. 로컬 환경 파일 생성
cp .env.example .env

# 5. 무작위 암호화 시크릿 생성
node -e "
  const fs = require('fs');
  const crypto = require('crypto');
  const p = '.env';
  const content = fs.readFileSync(p, 'utf8');
  fs.writeFileSync(p, content.replace('__CHANGE_ME__', crypto.randomBytes(32).toString('hex')));
"

# 6. AGENTS.md 오케스트레이션 규칙 설정 (AI 에이전트에게 Claw-Empire 프로젝트 매니저 역할을 부여)
pnpm setup -- --port 8790

# 7. 개발 서버 시작
pnpm dev:local
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# 1. 저장소 클론
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. corepack으로 pnpm 활성화
corepack enable

# 3. 의존성 설치
pnpm install

# 4. 로컬 환경 파일 생성
Copy-Item .env.example .env

# 5. 무작위 암호화 시크릿 생성
node -e "const fs=require('fs');const crypto=require('crypto');const p='.env';const c=fs.readFileSync(p,'utf8');fs.writeFileSync(p,c.replace('__CHANGE_ME__',crypto.randomBytes(32).toString('hex')))"

# 6. AGENTS.md 오케스트레이션 규칙 설정 (AI 에이전트에게 Claw-Empire 프로젝트 매니저 역할을 부여)
pnpm setup -- --port 8790

# 7. 개발 서버 시작
pnpm dev:local
```

</details>

### AGENTS.md 설정

`pnpm setup` 명령은 AI 에이전트의 `AGENTS.md` 파일에 **CEO 디렉티브 오케스트레이션 규칙**을 주입합니다. 이를 통해 AI 코딩 에이전트(Claude Code, Codex 등)가 다음을 수행할 수 있습니다:

- `$` 접두사 **CEO 디렉티브** 해석 및 우선순위 태스크 위임
- Claw-Empire REST API 호출로 태스크 생성, 에이전트 배정, 상태 보고
- 안전한 병렬 개발을 위한 독립 git worktree 환경에서 작업

```bash
# 기본: AGENTS.md 위치 자동 감지
pnpm setup

# 커스텀 경로
pnpm setup -- --agents-path /path/to/your/AGENTS.md

# 커스텀 포트
pnpm setup -- --port 8790
```

<a id="openclaw-integration"></a>
### OpenClaw 연동 셋업 (Telegram/Discord/Slack)

`install.sh` / `install.ps1` (또는 `scripts/openclaw-setup.*`)은 가능한 경우 `OPENCLAW_CONFIG`를 자동 감지하여 `.env`에 기록합니다.

권장 `.env` 형식: `OPENCLAW_CONFIG`는 절대경로(따옴표 없이 권장).
`v1.0.5`에서는 호환성을 위해 따옴표/선행 `~` 값도 런타임에서 정규화됩니다.

기본 경로:

| OS | 경로 |
|----|------|
| **macOS / Linux** | `~/.openclaw/openclaw.json` |
| **Windows** | `%USERPROFILE%\.openclaw\openclaw.json` |

수동 실행:

```bash
# macOS / Linux
bash scripts/openclaw-setup.sh --openclaw-config ~/.openclaw/openclaw.json
```

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1 -OpenClawConfig "$env:USERPROFILE\.openclaw\openclaw.json"
```

세션 확인:

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

<a id="dollar-command-logic"></a>
### `$` 명령어 기반 OpenClaw 채팅 의뢰 로직

채팅 메시지가 `$`로 시작하면 Claw-Empire는 CEO 디렉티브로 처리합니다.

1. 오케스트레이터가 팀장 회의 진행 여부를 먼저 확인합니다.
2. 오케스트레이터가 작업 프로젝트 경로/컨텍스트(`project_path` 또는 `project_context`)를 확인합니다.
3. `$` 접두사가 포함된 메시지를 `x-inbox-secret` 헤더와 함께 `POST /api/inbox`로 전달합니다.
4. 회의를 생략하면 `"skipPlannedMeeting": true`를 함께 보냅니다.
5. 서버는 이를 `directive`로 저장하고 전체 공지 후 기획팀(및 멘션된 부서)에 위임합니다.

`x-inbox-secret`가 없거나 `INBOX_WEBHOOK_SECRET`와 불일치하면 서버는 `401`을 반환합니다.
서버에 `INBOX_WEBHOOK_SECRET`이 설정되지 않으면 `503`을 반환합니다.

회의 포함:

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -H "x-inbox-secret: $INBOX_WEBHOOK_SECRET" \
  -d '{"source":"telegram","author":"ceo","text":"$금요일까지 QA 승인 포함 v0.2 배포 준비","project_path":"/Users/me/Projects/climpire"}'
```

회의 생략:

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -H "x-inbox-secret: $INBOX_WEBHOOK_SECRET" \
  -d '{"source":"telegram","author":"ceo","text":"$프로덕션 로그인 버그 즉시 핫픽스","skipPlannedMeeting":true,"project_context":"기존 작업하던 climpire 프로젝트"}'
```

브라우저에서 접속:

| URL | 설명 |
|-----|------|
| `http://127.0.0.1:8800` | Frontend (Vite 개발 서버) |
| `http://127.0.0.1:8790/healthz` | API 헬스 체크 |

---

## 환경 변수

`.env.example`을 `.env`로 복사하세요. 모든 시크릿은 로컬에 저장됩니다 — `.env`는 절대 커밋하지 마세요.

| 변수 | 필수 여부 | 설명 |
|------|----------|------|
| `OAUTH_ENCRYPTION_SECRET` | **필수** | SQLite의 OAuth 토큰 암호화에 사용 |
| `PORT` | 선택 | 서버 포트 (기본값: `8790`) |
| `HOST` | 선택 | 바인드 주소 (기본값: `127.0.0.1`) |
| `API_AUTH_TOKEN` | 권장 | 루프백 외부 API/WebSocket 접근용 Bearer 토큰 |
| `INBOX_WEBHOOK_SECRET` | **`/api/inbox` 사용 시 필수** | `x-inbox-secret` 헤더와 일치해야 하는 공유 시크릿 |
| `OPENCLAW_CONFIG` | OpenClaw 사용 시 권장 | 게이트웨이 타깃 조회/채팅 릴레이에 사용하는 `openclaw.json` 절대경로 |
| `DB_PATH` | 선택 | SQLite 데이터베이스 경로 (기본값: `./claw-empire.sqlite`) |
| `LOGS_DIR` | 선택 | 로그 디렉토리 (기본값: `./logs`) |
| `OAUTH_GITHUB_CLIENT_ID` | 선택 | GitHub OAuth 앱 클라이언트 ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | 선택 | GitHub OAuth 앱 클라이언트 시크릿 |
| `OAUTH_GOOGLE_CLIENT_ID` | 선택 | Google OAuth 클라이언트 ID |
| `OAUTH_GOOGLE_CLIENT_SECRET` | 선택 | Google OAuth 클라이언트 시크릿 |
| `OPENAI_API_KEY` | 선택 | OpenAI API 키 (Codex용) |

`API_AUTH_TOKEN`을 활성화하면 원격 브라우저 클라이언트는 런타임에 토큰을 입력합니다. 토큰은 `sessionStorage`에만 저장되며 Vite 빌드 산출물에는 포함되지 않습니다.
`OPENCLAW_CONFIG`는 절대경로를 권장하며, `v1.0.5`에서는 따옴표/선행 `~` 값도 자동 정규화됩니다.

---

## 실행 모드

```bash
# 개발 (로컬 전용, 권장)
pnpm dev:local          # 127.0.0.1에 바인딩

# 개발 (네트워크 접근 가능)
pnpm dev                # 0.0.0.0에 바인딩

# 프로덕션 빌드
pnpm build              # TypeScript 검사 + Vite 빌드
pnpm start              # 빌드된 서버 실행

# 헬스 체크
curl -fsS http://127.0.0.1:8790/healthz
```

---

## CLI 프로바이더 설정

Claw-Empire는 여러 CLI 기반 AI 코딩 어시스턴트와 함께 동작합니다. 최소 하나 이상 설치하세요:

| 프로바이더 | 설치 | 인증 |
|-----------|------|------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm i -g @anthropic-ai/claude-code` | `claude` (안내에 따라 진행) |
| [Codex CLI](https://github.com/openai/codex) | `npm i -g @openai/codex` | `.env`에 `OPENAI_API_KEY` 설정 |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `npm i -g @google/gemini-cli` | 설정 패널에서 OAuth 인증 |
| [OpenCode](https://github.com/opencode-ai/opencode) | `npm i -g opencode` | 프로바이더별 설정 |

앱 내 **Settings > CLI Tools** 패널에서 프로바이더와 모델을 설정하세요.

---

## 프로젝트 구조

```
claw-empire/
├── server/
│   └── index.ts              # Express 5 + SQLite + WebSocket 백엔드
├── src/
│   ├── App.tsx                # React Router를 사용하는 메인 React 앱
│   ├── api.ts                 # Frontend API 클라이언트
│   ├── i18n.ts                # 다국어 지원 (en/ko/ja/zh)
│   ├── components/
│   │   ├── OfficeView.tsx     # PixiJS 에이전트가 구현된 픽셀 아트 오피스
│   │   ├── Dashboard.tsx      # KPI 지표 및 차트
│   │   ├── TaskBoard.tsx      # 칸반 스타일 태스크 관리
│   │   ├── ChatPanel.tsx      # CEO-에이전트 커뮤니케이션
│   │   ├── SettingsPanel.tsx  # 회사 및 프로바이더 설정
│   │   ├── SkillsLibrary.tsx  # 에이전트 스킬 관리
│   │   └── TerminalPanel.tsx  # 실시간 CLI 출력 뷰어
│   ├── hooks/                 # usePolling, useWebSocket
│   └── types/                 # TypeScript 타입 정의
├── public/sprites/            # 12종의 픽셀 아트 에이전트 스프라이트
├── scripts/
│   ├── openclaw-setup.sh      # 원클릭 셋업 (macOS/Linux)
│   ├── openclaw-setup.ps1     # 원클릭 셋업 (Windows PowerShell)
│   ├── preflight-public.sh    # 릴리즈 전 보안 검사
│   └── generate-architecture-report.mjs
├── install.sh                 # scripts/openclaw-setup.sh 실행 래퍼
├── install.ps1                # scripts/openclaw-setup.ps1 실행 래퍼
├── docs/                      # 설계 및 아키텍처 문서
├── .env.example               # 환경 변수 템플릿
└── package.json
```

---

## 보안

Claw-Empire는 보안을 최우선으로 설계되었습니다:

- **로컬 퍼스트 아키텍처** — 모든 데이터는 SQLite에 로컬로 저장; 외부 클라우드 서비스 불필요
- **암호화된 OAuth 토큰** — 사용자 OAuth 토큰은 **서버 측 SQLite에만 저장**되며, `OAUTH_ENCRYPTION_SECRET`을 사용해 AES-256-GCM으로 암호화됩니다. 브라우저에는 리프레시 토큰이 전달되지 않습니다
- **빌트인 OAuth Client ID** — 소스 코드에 포함된 GitHub/Google OAuth client ID/secret은 **공개 OAuth 앱 자격증명**이며 사용자 시크릿이 아닙니다. [Google 문서](https://developers.google.com/identity/protocols/oauth2/native-app)에 따르면 설치형/데스크톱 앱의 client secret은 "시크릿으로 취급되지 않습니다." 이는 오픈소스 앱(VS Code, Thunderbird, GitHub CLI 등)의 표준 관행입니다. 이 자격증명은 앱 자체를 식별할 뿐이며, 개인 토큰은 항상 별도로 암호화됩니다
- **소스 코드에 개인 자격증명 없음** — 모든 사용자별 토큰(GitHub, Google OAuth)은 로컬 SQLite에 암호화되어 저장되며, 소스 코드에는 포함되지 않습니다
- **저장소에 시크릿 없음** — 포괄적인 `.gitignore`로 `.env`, `*.pem`, `*.key`, `credentials.json` 등 차단
- **프리플라이트 보안 검사** — 공개 릴리즈 전 `pnpm run preflight:public` 실행으로 작업 트리와 git 히스토리의 유출된 시크릿 스캔
- **기본값은 localhost** — 개발 서버는 `127.0.0.1`에 바인딩되어 네트워크에 노출되지 않음

---

## 기여하기

기여를 환영합니다! 다음 절차를 따라주세요:

1. 저장소를 포크합니다
2. 기능 브랜치를 생성합니다 (`git checkout -b feature/amazing-feature`)
3. 변경 사항을 커밋합니다 (`git commit -m 'Add amazing feature'`)
4. 브랜치에 푸시합니다 (`git push origin feature/amazing-feature`)
5. Pull Request를 엽니다

---

## 라이선스

[Apache 2.0](LICENSE) — 개인 및 상업적 사용 모두 무료.

---

<div align="center">

**픽셀과 열정으로 만들었습니다.**

*Claw-Empire — AI 에이전트들이 일하러 오는 곳.*

</div>
