import { useState, useEffect } from "react";
import type { CompanySettings, CliStatusMap, CliProvider } from "../types";
import * as api from "../api";
import type { OAuthStatus, OAuthConnectProvider } from "../api";
import type { OAuthCallbackResult } from "../App";

interface SettingsPanelProps {
  settings: CompanySettings;
  cliStatus: CliStatusMap | null;
  onSave: (settings: CompanySettings) => void;
  onRefreshCli: () => void;
  oauthResult?: OAuthCallbackResult | null;
  onOauthResultClear?: () => void;
}

const CLI_INFO: Record<string, { label: string; icon: string }> = {
  claude: { label: "Claude Code", icon: "🟣" },
  codex: { label: "Codex CLI", icon: "🟢" },
  gemini: { label: "Gemini CLI", icon: "🔵" },
  opencode: { label: "OpenCode", icon: "⚪" },
  copilot: { label: "GitHub Copilot", icon: "⚫" },
  antigravity: { label: "Antigravity", icon: "🟡" },
};

const OAUTH_INFO: Record<string, { label: string; icon: string }> = {
  github: { label: "GitHub", icon: "🐙" },
  copilot: { label: "GitHub Copilot", icon: "⚫" },
  google: { label: "Google Cloud", icon: "☁️" },
  antigravity: { label: "Antigravity", icon: "🟡" },
};

export default function SettingsPanel({
  settings,
  cliStatus,
  onSave,
  onRefreshCli,
  oauthResult,
  onOauthResultClear,
}: SettingsPanelProps) {
  const [form, setForm] = useState<CompanySettings>(settings);
  const [saved, setSaved] = useState(false);
  const [tab, setTab] = useState<"general" | "cli" | "oauth">(
    oauthResult ? "oauth" : "general"
  );
  const [oauthStatus, setOauthStatus] = useState<OAuthStatus | null>(null);
  const [oauthLoading, setOauthLoading] = useState(false);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);

  useEffect(() => {
    setForm(settings);
  }, [settings]);

  // Auto-switch to oauth tab when callback result arrives
  useEffect(() => {
    if (oauthResult) {
      setTab("oauth");
      // Force refresh oauth status
      setOauthStatus(null);
    }
  }, [oauthResult]);

  useEffect(() => {
    if (tab === "oauth" && !oauthStatus) {
      setOauthLoading(true);
      api.getOAuthStatus()
        .then(setOauthStatus)
        .catch(console.error)
        .finally(() => setOauthLoading(false));
    }
  }, [tab, oauthStatus]);

  // Auto-dismiss oauth result banner after 8 seconds
  useEffect(() => {
    if (oauthResult) {
      const timer = setTimeout(() => onOauthResultClear?.(), 8000);
      return () => clearTimeout(timer);
    }
  }, [oauthResult, onOauthResultClear]);

  function handleSave() {
    onSave(form);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function handleConnect(provider: OAuthConnectProvider) {
    const redirectTo = window.location.origin + window.location.pathname;
    window.location.assign(api.getOAuthStartUrl(provider, redirectTo));
  }

  async function handleDisconnect(provider: OAuthConnectProvider) {
    setDisconnecting(provider);
    try {
      await api.disconnectOAuth(provider);
      // Refresh status
      const status = await api.getOAuthStatus();
      setOauthStatus(status);
    } catch (err) {
      console.error("Disconnect failed:", err);
    } finally {
      setDisconnecting(null);
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <h2 className="text-xl font-bold text-white flex items-center gap-2">
        ⚙️ 설정
      </h2>

      {/* Tab navigation */}
      <div className="flex border-b border-slate-700/50">
        {[
          { key: "general", label: "일반 설정", icon: "⚙️" },
          { key: "cli", label: "CLI 도구", icon: "🔧" },
          { key: "oauth", label: "OAuth 인증", icon: "🔑" },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key as typeof tab)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors ${
              tab === t.key
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>{t.icon}</span>
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* General Settings Tab */}
      {tab === "general" && (
      <>
      <section className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          회사 정보
        </h3>

        <div>
          <label className="block text-xs text-slate-400 mb-1">회사명</label>
          <input
            type="text"
            value={form.companyName}
            onChange={(e) =>
              setForm({ ...form, companyName: e.target.value })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">CEO 이름</label>
          <input
            type="text"
            value={form.ceoName}
            onChange={(e) =>
              setForm({ ...form, ceoName: e.target.value })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-3">
          <label className="text-sm text-slate-300">자동 배정</label>
          <button
            onClick={() =>
              setForm({ ...form, autoAssign: !form.autoAssign })
            }
            className={`w-10 h-5 rounded-full transition-colors relative ${
              form.autoAssign ? "bg-blue-500" : "bg-slate-600"
            }`}
          >
            <div
              className={`w-4 h-4 bg-white rounded-full absolute top-0.5 transition-all ${
                form.autoAssign ? "left-5.5" : "left-0.5"
              }`}
            />
          </button>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            기본 CLI 프로바이더
          </label>
          <select
            value={form.defaultProvider}
            onChange={(e) =>
              setForm({
                ...form,
                defaultProvider: e.target.value as CliProvider,
              })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="claude">Claude Code</option>
            <option value="codex">Codex CLI</option>
            <option value="gemini">Gemini CLI</option>
            <option value="opencode">OpenCode</option>
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">언어</label>
          <select
            value={form.language}
            onChange={(e) =>
              setForm({
                ...form,
                language: e.target.value as "ko" | "en",
              })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="ko">한국어</option>
            <option value="en">English</option>
          </select>
        </div>
      </section>

      {/* Save */}
      <div className="flex justify-end gap-3">
        {saved && (
          <span className="text-green-400 text-sm self-center">
            ✅ 저장 완료
          </span>
        )}
        <button
          onClick={handleSave}
          className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          저장
        </button>
      </div>
      </>
      )}

      {/* CLI Status Tab */}
      {tab === "cli" && (
      <section className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            CLI 도구 상태
          </h3>
          <button
            onClick={onRefreshCli}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            🔄 새로고침
          </button>
        </div>

        {cliStatus ? (
          <div className="space-y-2">
            {Object.entries(cliStatus).map(([provider, status]) => {
              const info = CLI_INFO[provider];
              return (
                <div
                  key={provider}
                  className="flex items-center gap-3 bg-slate-700/30 rounded-lg p-3"
                >
                  <span className="text-lg">{info?.icon ?? "❓"}</span>
                  <div className="flex-1">
                    <div className="text-sm text-white">
                      {info?.label ?? provider}
                    </div>
                    <div className="text-xs text-slate-500">
                      {status.version ?? "미설치"}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full ${
                        status.installed
                          ? "bg-green-500/20 text-green-400"
                          : "bg-slate-600/50 text-slate-400"
                      }`}
                    >
                      {status.installed ? "설치됨" : "미설치"}
                    </span>
                    {status.installed && (
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full ${
                          status.authenticated
                            ? "bg-blue-500/20 text-blue-400"
                            : "bg-yellow-500/20 text-yellow-400"
                        }`}
                      >
                        {status.authenticated ? "인증됨" : "미인증"}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-4 text-slate-500 text-sm">
            로딩 중...
          </div>
        )}

        <p className="text-xs text-slate-500">
          각 에이전트의 CLI 도구는 오피스에서 에이전트 클릭 후 변경할 수 있습니다.
        </p>
      </section>
      )}

      {/* OAuth Tab */}
      {tab === "oauth" && (
      <section className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            OAuth 인증 현황
          </h3>
          <button
            onClick={() => {
              setOauthStatus(null);
              setOauthLoading(true);
              api.getOAuthStatus()
                .then(setOauthStatus)
                .catch(console.error)
                .finally(() => setOauthLoading(false));
            }}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            🔄 새로고침
          </button>
        </div>

        {/* OAuth callback result banner */}
        {oauthResult && (
          <div className={`flex items-center justify-between px-3 py-2 rounded-lg text-sm ${
            oauthResult.error
              ? "bg-red-500/10 text-red-400 border border-red-500/20"
              : "bg-green-500/10 text-green-400 border border-green-500/20"
          }`}>
            <span>
              {oauthResult.error
                ? `OAuth 연결 실패: ${oauthResult.error}`
                : `${OAUTH_INFO[oauthResult.provider || ""]?.label || oauthResult.provider} 연결 완료!`}
            </span>
            <button
              onClick={() => onOauthResultClear?.()}
              className="text-xs opacity-60 hover:opacity-100 ml-2"
            >
              ✕
            </button>
          </div>
        )}

        {/* Storage status */}
        {oauthStatus && (
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${
            oauthStatus.storageReady
              ? "bg-green-500/10 text-green-400 border border-green-500/20"
              : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
          }`}>
            <span>{oauthStatus.storageReady ? "🔒" : "⚠️"}</span>
            <span>
              {oauthStatus.storageReady
                ? "OAuth 저장소 활성화됨 (암호화 키 설정됨)"
                : "OAUTH_ENCRYPTION_SECRET 환경변수가 설정되지 않았습니다"}
            </span>
          </div>
        )}

        {oauthLoading ? (
          <div className="text-center py-8 text-slate-500 text-sm">
            로딩 중...
          </div>
        ) : oauthStatus ? (
          Object.keys(oauthStatus.providers).length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              <div className="text-3xl mb-2">🔑</div>
              <div className="text-sm">등록된 OAuth 인증 정보가 없습니다</div>
              <div className="text-xs mt-1 text-slate-600">
                CLI 도구를 인증하거나 아래 "연결하기" 버튼을 사용하세요
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              {Object.entries(oauthStatus.providers).map(([provider, info]) => {
                const oauthInfo = OAUTH_INFO[provider];
                const expiresAt = info.expires_at ? new Date(info.expires_at) : null;
                const isExpired = expiresAt ? expiresAt.getTime() < Date.now() : false;
                const isWebOAuth = info.source === "web-oauth";
                const isFileDetected = info.source === "file-detected";
                const isConnectable = info.webConnectable && (provider === "github" || provider === "google");
                return (
                  <div
                    key={provider}
                    className="bg-slate-700/30 rounded-lg p-4 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{oauthInfo?.icon ?? "🔑"}</span>
                        <span className="text-sm font-medium text-white">
                          {oauthInfo?.label ?? provider}
                        </span>
                        {isFileDetected && info.connected && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-600/50 text-slate-400">
                            CLI에서 감지됨
                          </span>
                        )}
                        {isWebOAuth && info.connected && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
                            웹 OAuth
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          info.connected && !isExpired
                            ? "bg-green-500/20 text-green-400"
                            : isExpired
                            ? "bg-red-500/20 text-red-400"
                            : "bg-slate-600/50 text-slate-400"
                        }`}>
                          {info.connected && !isExpired ? "연결됨" : isExpired ? "만료됨" : "미연결"}
                        </span>

                        {/* Connect / Disconnect buttons */}
                        {isConnectable && oauthStatus.storageReady && !isWebOAuth && (
                          <button
                            onClick={() => handleConnect(provider as OAuthConnectProvider)}
                            className="text-xs px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
                          >
                            {isFileDetected ? "웹 OAuth로 연결" : "연결하기"}
                          </button>
                        )}
                        {isConnectable && !oauthStatus.storageReady && !isWebOAuth && (
                          <button
                            disabled
                            className="text-xs px-2.5 py-1 rounded-lg bg-slate-600/50 text-slate-500 cursor-not-allowed"
                            title="OAUTH_ENCRYPTION_SECRET 설정 필요"
                          >
                            연결하기
                          </button>
                        )}
                        {(provider === "github" || provider === "google") && !info.webConnectable && !info.connected && (
                          <span className="text-[10px] text-slate-500">Client ID 미설정</span>
                        )}
                        {isWebOAuth && info.connected && (
                          <button
                            onClick={() => handleDisconnect(provider as OAuthConnectProvider)}
                            disabled={disconnecting === provider}
                            className="text-xs px-2.5 py-1 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 transition-colors disabled:opacity-50"
                          >
                            {disconnecting === provider ? "해제 중..." : "연결 해제"}
                          </button>
                        )}
                      </div>
                    </div>

                    {info.connected && (
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {info.email && (
                        <div>
                          <span className="text-slate-500">계정: </span>
                          <span className="text-slate-300">{info.email}</span>
                        </div>
                      )}
                      {info.source && (
                        <div>
                          <span className="text-slate-500">소스: </span>
                          <span className="text-slate-300">{info.source}</span>
                        </div>
                      )}
                      {info.scope && (
                        <div className="col-span-2">
                          <span className="text-slate-500">스코프: </span>
                          <span className="text-slate-300 font-mono text-[10px]">{info.scope}</span>
                        </div>
                      )}
                      {expiresAt && (
                        <div>
                          <span className="text-slate-500">만료: </span>
                          <span className={isExpired ? "text-red-400" : "text-slate-300"}>
                            {expiresAt.toLocaleString("ko-KR")}
                          </span>
                        </div>
                      )}
                      {info.created_at > 0 && (
                      <div>
                        <span className="text-slate-500">등록: </span>
                        <span className="text-slate-300">
                          {new Date(info.created_at).toLocaleString("ko-KR")}
                        </span>
                      </div>
                      )}
                    </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
        ) : null}
      </section>
      )}
    </div>
  );
}
