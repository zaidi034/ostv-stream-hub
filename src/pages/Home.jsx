import React, { useEffect, useState } from "react";
import { base44 } from "@/api/base44Client";
import { Link } from "react-router-dom";
import { Tv, Clapperboard, MonitorPlay, Loader2, Shield } from "lucide-react";
import ContentCard from "@/components/ContentCard";
import ChannelCard from "@/components/ChannelCard";

const TABS = [
  { id: "channels", label: "قنوات مباشرة", icon: Tv },
  { id: "movies", label: "أفلام", icon: Clapperboard },
  { id: "series", label: "مسلسلات", icon: MonitorPlay },
];

export default function Home() {
  const [tab, setTab] = useState("channels");
  const [channels, setChannels] = useState(null);
  const [movies, setMovies] = useState(null);
  const [series, setSeries] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    base44.entities.Channel.list("-created_date", 300).then(setChannels);
    base44.entities.Movie.list("-year", 150).then(setMovies);
    base44.entities.Serie.list("-year", 150).then(setSeries);
    base44.auth.me().then((me) => setIsAdmin(me && me.role === "admin")).catch(() => {});
  }, []);

  const channelGroups = React.useMemo(() => {
    const groups = {};
    for (const ch of channels || []) {
      const g = ch.group_name || "قنوات";
      if (!groups[g]) groups[g] = [];
      groups[g].push(ch);
    }
    return groups;
  }, [channels]);

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <header className="sticky top-0 z-10 bg-background/90 backdrop-blur border-b border-border">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link to="/" className="text-xl font-bold font-heading text-primary">
              OS <span className="text-red-500">TV</span>
            </Link>
            {isAdmin && (
              <Link
                to="/admin"
                title="لوحة الأدمن"
                className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground border border-border rounded-lg px-2 py-1"
              >
                <Shield className="w-3.5 h-3.5" /> أدمن
              </Link>
            )}
          </div>
          <nav className="flex gap-1 p-1 rounded-xl bg-muted">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={
                  "flex items-center gap-1.5 px-3 sm:px-4 py-1.5 rounded-lg text-sm font-medium transition-colors " +
                  (tab === id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")
                }
              >
                <Icon className="w-4 h-4" />
                <span className="hidden sm:inline">{label}</span>
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6">
        {tab === "channels" && (
          channels === null ? (
            <Loading />
          ) : channels.length === 0 ? (
            <Empty text="لا توجد قنوات مستوردة بعد" />
          ) : (
            Object.entries(channelGroups).map(([group, list]) => (
              <section key={group} className="mb-8">
                <h2 className="text-lg font-bold mb-3 flex items-center gap-2">
                  <span className="w-1.5 h-5 bg-red-500 rounded" />
                  {group}
                </h2>
                <div className="flex gap-3 overflow-x-auto pb-2">
                  {list.map((ch) => (
                    <ChannelCard
                      key={ch.id}
                      sourceId={ch.source_id}
                      name={ch.name}
                      logoUrl={ch.logo_url}
                    />
                  ))}
                </div>
              </section>
            ))
          )
        )}

        {tab === "movies" && (
          movies === null ? (
            <Loading />
          ) : movies.length === 0 ? (
            <Empty text="لا توجد أفلام مستوردة بعد" />
          ) : (
            <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-x-3 gap-y-5">
              {movies.map((m) => (
                <ContentCard
                  key={m.id}
                  to={"/movie/" + m.source_id}
                  posterUrl={m.poster_url}
                  title={m.title}
                  year={m.year}
                  rating={m.rating}
                />
              ))}
            </div>
          )
        )}

        {tab === "series" && (
          series === null ? (
            <Loading />
          ) : series.length === 0 ? (
            <Empty text="لا توجد مسلسلات مستوردة بعد" />
          ) : (
            <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-x-3 gap-y-5">
              {series.map((s) => (
                <ContentCard
                  key={s.id}
                  to={"/serie/" + s.source_id}
                  posterUrl={s.poster_url}
                  title={s.title}
                  year={s.year}
                  rating={s.rating}
                />
              ))}
            </div>
          )
        )}
      </main>
    </div>
  );
}

const Loading = () => (
  <div className="flex items-center justify-center py-20 text-muted-foreground">
    <Loader2 className="w-6 h-6 animate-spin" />
  </div>
);

const Empty = ({ text }) => (
  <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-2">
    <Tv className="w-10 h-10" />
    <p className="text-sm">{text}</p>
  </div>
);