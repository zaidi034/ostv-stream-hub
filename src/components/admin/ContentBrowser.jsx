import React, { useEffect, useState } from "react";
import { base44 } from "@/api/base44Client";
import { Link } from "react-router-dom";
import { Loader2, Search, Play, X } from "lucide-react";
import VideoPlayer from "@/components/VideoPlayer";

const TABS = [
  { id: "channels", label: "قنوات", entity: "Channel", to: (id) => "/channel/" + id, title: (r) => r.name },
  { id: "movies", label: "أفلام", entity: "Movie", to: (id) => "/movie/" + id, title: (r) => r.title },
  { id: "series", label: "مسلسلات", entity: "Serie", to: (id) => "/serie/" + id, title: (r) => r.title },
  { id: "episodes", label: "حلقات", entity: "Episode", title: (r) => r.title },
];

export default function ContentBrowser() {
  const [tab, setTab] = useState("channels");
  const [items, setItems] = useState(null);
  const [query, setQuery] = useState("");
  const [episode, setEpisode] = useState(null); // { ep, links, linkIdx, loading }

  const cfg = TABS.find((t) => t.id === tab);

  useEffect(() => {
    setItems(null);
    setEpisode(null);
    base44.entities[cfg.entity].list("-created_date", 300).then(setItems);
  }, [tab]);

  const pickEpisode = async (ep) => {
    setEpisode({ ep, links: null, linkIdx: 0 });
    try {
      const res = await base44.functions.invoke("oscarStream", { type: "episode", id: ep.source_id });
      setEpisode({ ep, links: (res.data && res.data.watch_links) || [], linkIdx: 0 });
    } catch {
      setEpisode({ ep, links: [], linkIdx: 0 });
    }
  };

  const filtered = (items || []).filter((r) =>
    !query || (cfg.title(r) || "").toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex flex-wrap gap-1.5">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={
                "px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors " +
                (tab === t.id
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border text-muted-foreground hover:text-foreground")
              }
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="relative">
          <Search className="w-4 h-4 absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="بحث بالاسم..."
            className="rounded-lg border border-input bg-background pl-3 pr-9 py-1.5 text-sm w-44"
          />
        </div>
      </div>

      {episode && (
        <div className="mb-5 rounded-xl border border-border bg-card p-4">
          <div className="flex items-center justify-between gap-2 mb-3">
            <h3 className="text-sm font-bold">{episode.ep.title}</h3>
            <button onClick={() => setEpisode(null)} className="text-muted-foreground hover:text-foreground">
              <X className="w-4 h-4" />
            </button>
          </div>
          {episode.links === null ? (
            <div className="w-full aspect-video bg-black rounded-xl flex items-center justify-center">
              <Loader2 className="w-6 h-6 animate-spin text-white" />
            </div>
          ) : episode.links.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">لا توجد روابط مشاهدة لهذه الحلقة</p>
          ) : (
            <>
              {episode.links.length > 1 && (
                <div className="flex flex-wrap gap-2 mb-3">
                  {episode.links.map((l, i) => (
                    <button
                      key={i}
                      onClick={() => setEpisode((s) => ({ ...s, linkIdx: i }))}
                      className={
                        "px-3 py-1 rounded-lg text-xs font-medium border " +
                        (i === episode.linkIdx
                          ? "bg-primary text-primary-foreground border-primary"
                          : "border-border text-muted-foreground hover:text-foreground")
                      }
                    >
                      {l.quality || l.name}
                    </button>
                  ))}
                </div>
              )}
              <VideoPlayer src={episode.links[episode.linkIdx]?.url} />
            </>
          )}
        </div>
      )}

      {items === null ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="w-6 h-6 animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <p className="text-sm text-muted-foreground text-center py-16">
          لا توجد عناصر محفوظة — استخدم تبويب «جلب المحتوى» أولًا
        </p>
      ) : (
        <div className="grid gap-2">
          {filtered.map((r) => {
            const inner = (
              <>
                <span className="w-16 shrink-0 rounded bg-muted px-1.5 py-0.5 text-center text-[11px] font-mono text-muted-foreground">
                  #{r.source_id}
                </span>
                <span className="flex-1 truncate text-sm">{cfg.title(r)}</span>
                {cfg.to ? (
                  <span className="text-xs text-primary shrink-0">فتح</span>
                ) : (
                  <Play className="w-4 h-4 text-primary shrink-0" />
                )}
              </>
            );
            return cfg.to ? (
              <Link
                key={r.id}
                to={cfg.to(r.source_id)}
                className="flex items-center gap-3 rounded-lg border border-border bg-card px-3 py-2.5 hover:bg-muted transition-colors"
              >
                {inner}
              </Link>
            ) : (
              <button
                key={r.id}
                onClick={() => pickEpisode(r)}
                className={
                  "flex items-center gap-3 rounded-lg border bg-card px-3 py-2.5 transition-colors text-right " +
                  (episode && episode.ep.id === r.id ? "border-primary" : "border-border hover:bg-muted")
                }
              >
                {inner}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}