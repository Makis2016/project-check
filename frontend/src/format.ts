import type { Summary } from "./types";

export function formatTime(epoch: number | null | undefined): string {
  if (!epoch) return "—";
  const date = new Date(epoch * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (!ms) return "—";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} 分 ${Math.round(seconds % 60)} 秒`;
}

export function riskLevel(summary: Summary | null): { label: string; tone: string } {
  if (!summary || summary.total === 0) return { label: "良好", tone: "low" };
  if (summary.critical > 0) return { label: "严重", tone: "critical" };
  if (summary.high > 0) return { label: "高风险", tone: "high" };
  if (summary.medium > 0) return { label: "中风险", tone: "medium" };
  if (summary.low > 0) return { label: "低风险", tone: "low" };
  return { label: "信息", tone: "info" };
}

export const PRESET_LABEL: Record<string, string> = {
  quick: "快速体检",
  standard: "标准扫描",
  deep: "深度扫描",
};

export function hostOf(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
