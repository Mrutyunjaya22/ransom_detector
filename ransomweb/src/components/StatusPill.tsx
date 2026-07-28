import { cn } from "@/lib/utils";

export function StatusPill({
  label,
  state,
  detail,
}: {
  label: string;
  state: "ok" | "warn" | "danger" | "idle";
  detail?: string;
}) {
  const dot = {
    ok: "bg-ok",
    warn: "bg-warn",
    danger: "bg-danger",
    idle: "bg-muted-foreground",
  }[state];

  return (
    <div className="flex items-center gap-3 rounded-md border border-border bg-surface px-3 py-2">
      <span className={cn("size-2 rounded-full live-dot", dot)} />
      <div className="min-w-0">
        <p className="text-xs uppercase tracking-wider text-muted-foreground">{label}</p>
        <p className="truncate font-mono text-sm">{detail}</p>
      </div>
    </div>
  );
}