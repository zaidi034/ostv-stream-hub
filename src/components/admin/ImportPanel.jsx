import React, { useState } from "react";
import { base44 } from "@/api/base44Client";
import { Button } from "@/components/ui/button";
import { Loader2, Play, CheckCircle2, AlertCircle } from "lucide-react";

const TYPES = [
  { id: "movies", label: "أفلام" },
  { id: "series", label: "مسلسلات" },
  { id: "episodes", label: "حلقات" },
  { id: "channels", label: "قنوات" },
];

export default function ImportPanel() {
  const [type, setType] = useState("movies");
  const [start, setStart] = useState(1);
  const [end, setEnd] = useState(600);
  const [running, setRunning] = useState(false);
  const [history, setHistory] = useState([]);

  const runImport = async () => {
    setRunning(true);
    try {
      const res = await base44.functions.invoke("oscarImport", {
        type,
        start: Number(start),
        end: Number(end),
      });
      setHistory((h) => [{ ...res.data, at: new Date() }, ...h].slice(0, 20));
    } catch (e) {
      setHistory((h) => [{ type, error: e.message, at: new Date() }, ...h].slice(0, 20));
    }
    setRunning(false);
  };

  return (
    <div>
      <div className="rounded-xl border border-border bg-card p-4 sm:p-5">
        <h1 className="text-lg font-bold mb-1">جلب المحتوى وحفظه في قاعدة البيانات</h1>
        <p className="text-sm text-muted-foreground mb-4">
          يتم مسح المعرّفات من المصدر وحفظ التفاصيل (العنوان، المعرّف، البوستر)، وتُجلب روابط المشاهدة لاحقًا عند النقر عليها.
        </p>

        <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto_auto] sm:items-end">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">نوع المحتوى</label>
            <div className="flex flex-wrap gap-1.5">
              {TYPES.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setType(t.id)}
                  disabled={running}
                  className={
                    "px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors " +
                    (type === t.id
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border text-muted-foreground hover:text-foreground")
                  }
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {type !== "channels" && (
            <div>
              <label className="text-xs text-muted-foreground block mb-1">من</label>
              <input
                type="number"
                min={1}
                value={start}
                onChange={(e) => setStart(e.target.value)}
                disabled={running}
                className="w-24 rounded-lg border border-input bg-background px-3 py-1.5 text-sm"
              />
            </div>
          )}
          {type !== "channels" && (
            <div>
              <label className="text-xs text-muted-foreground block mb-1">إلى</label>
              <input
                type="number"
                min={1}
                value={end}
                onChange={(e) => setEnd(e.target.value)}
                disabled={running}
                className="w-24 rounded-lg border border-input bg-background px-3 py-1.5 text-sm"
              />
            </div>
          )}

          <Button onClick={runImport} disabled={running || !type} className="gap-2">
            {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {running ? "جارٍ الجلب..." : "بدء الجلب"}
          </Button>
        </div>

        {type !== "channels" && (
          <p className="text-xs text-muted-foreground mt-3">
            الحد الأقصى للمدى في كل عملية 600 معرّف. المعرّفات الموجودة مسبقًا تُحدَّث ولا تتكرر.
          </p>
        )}
      </div>

      {history.length > 0 && (
        <section className="mt-5">
          <h2 className="text-sm font-bold mb-2">سجل العمليات</h2>
          <div className="space-y-2">
            {history.map((h, i) => (
              <div key={i} className="rounded-lg border border-border bg-card px-4 py-3 flex items-start gap-3">
                {h.error ? (
                  <AlertCircle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
                )}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">
                    {h.error ? "فشلت العملية" : "اكتملت العملية"} — {TYPES.find((t) => t.id === h.type)?.label || h.type}
                  </p>
                  {h.error ? (
                    <p className="text-xs text-muted-foreground">{h.error}</p>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {h.scanned != null && <>مسح: {h.scanned} · </>}
                      وجد: {h.found} · أُنشئ: {h.created} · حُدِّث: {h.updated}
                      {h.errors > 0 && <> · أخطاء: {h.errors}</>}
                      {h.lastError?.length > 0 && <span className="block text-destructive mt-1">{h.lastError[0]}</span>}
                    </p>
                  )}
                  <p className="text-[11px] text-muted-foreground mt-1">
                    {new Date(h.at).toLocaleTimeString("ar-TN")}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}