import React, { useEffect, useState } from "react";
import { base44 } from "@/api/base44Client";
import { Link, useParams } from "react-router-dom";
import { Image } from "@/components/ui/image";
import { ArrowRight, Loader2, Star, Play } from "lucide-react";
import VideoPlayer from "@/components/VideoPlayer";

export default function SeriePage() {
  const { sourceId } = useParams();
  const [serie, setSerie] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [seasonIdx, setSeasonIdx] = useState(0);
  const [episodes, setEpisodes] = useState(null);
  const [currentEp, setCurrentEp] = useState(null);
  const [linkIdx, setLinkIdx] = useState(0);
  const [epLinks, setEpLinks] = useState(null);

  useEffect(() => {
    setSerie(null);
    setNotFound(false);
    setCurrentEp(null);
    base44.entities.Serie.filter({ source_id: Number(sourceId) }, null, 1).then((r) => {
      if (r && r.length) setSerie(r[0]);
      else setNotFound(true);
    });
  }, [sourceId]);

  const seasons = serie?.seasons || [];
  const season = seasons[seasonIdx];

  useEffect(() => {
    if (!serie || !season) return;
    setEpisodes(null);
    setCurrentEp(null);
    base44.entities.Episode.filter(
      { series_id: serie.source_id, season_number: season.season_number },
      "number",
      500
    ).then(setEpisodes);
  }, [serie, season]);

  useEffect(() => {
    setLinkIdx(0);
    setEpLinks(null);
    if (!currentEp) return;
    base44.functions.invoke("oscarStream", { type: "episode", id: currentEp.source_id })
      .then((res) => { setEpLinks((res.data && res.data.watch_links) || []); setLinkIdx(0); })
      .catch(() => setEpLinks([]));
  }, [currentEp]);

  if (notFound) {
    return (
      <Center>
        <p>المسلسل غير موجود</p>
        <Link to="/" className="text-primary text-sm hover:underline">العودة للرئيسية</Link>
      </Center>
    );
  }
  if (!serie) {
    return <Center><Loader2 className="w-6 h-6 animate-spin" /></Center>;
  }

  const links = epLinks || [];

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <div className="max-w-4xl mx-auto px-4 py-6">
        <Link to="/" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-4">
          <ArrowRight className="w-4 h-4" /> العودة
        </Link>

        <div className="flex flex-col sm:flex-row gap-5 mb-6">
          <div className="w-32 sm:w-40 shrink-0 aspect-[2/3] rounded-xl overflow-hidden border border-border">
            {serie.poster_url && <Image src={serie.poster_url} alt={serie.title} className="w-full h-full object-cover" />}
          </div>
          <div className="flex-1">
            <h1 className="text-2xl font-bold">{serie.title}</h1>
            {serie.title_en && serie.title_en !== serie.title && (
              <p className="text-sm text-muted-foreground mt-1">{serie.title_en}</p>
            )}
            <div className="flex flex-wrap items-center gap-2 mt-3 text-sm text-muted-foreground">
              {serie.rating > 0 && (
                <span className="flex items-center gap-1 text-amber-400 font-medium">
                  <Star className="w-4 h-4" /> {Number(serie.rating).toFixed(1)}
                </span>
              )}
              {serie.year > 0 && <span>{serie.year}</span>}
              {serie.episode_count > 0 && <span>{serie.episode_count} حلقة</span>}
              {serie.country && <span>{serie.country}</span>}
            </div>
            {serie.story && <p className="text-sm text-muted-foreground leading-relaxed mt-3">{serie.story}</p>}
          </div>
        </div>

        {currentEp && (
          <div className="mb-6">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <h2 className="text-sm font-bold">
                {season?.title || "الموسم"} — {currentEp.title}
              </h2>
              <button onClick={() => setCurrentEp(null)} className="text-xs text-muted-foreground hover:text-foreground">
                إغلاق المشغل
              </button>
            </div>
            {links.length > 1 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {links.map((l, i) => (
                  <button
                    key={i}
                    onClick={() => setLinkIdx(i)}
                    className={
                      "px-3 py-1.5 rounded-lg text-sm font-medium border " +
                      (i === linkIdx
                        ? "bg-primary text-primary-foreground border-primary"
                        : "border-border text-muted-foreground hover:text-foreground")
                    }
                  >
                    {l.quality || l.name}
                  </button>
                ))}
              </div>
            )}
            {epLinks === null ? (
              <div className="w-full aspect-video bg-black rounded-xl flex items-center justify-center">
                <Loader2 className="w-6 h-6 animate-spin text-white" />
              </div>
            ) : (
              <VideoPlayer src={links[linkIdx]?.url} />
            )}
          </div>
        )}

        {seasons.length > 0 ? (
          <>
            <div className="flex gap-2 overflow-x-auto pb-2 mb-4">
              {seasons.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setSeasonIdx(i)}
                  className={
                    "px-4 py-2 rounded-lg text-sm font-medium shrink-0 border " +
                    (i === seasonIdx
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border text-muted-foreground hover:text-foreground")
                  }
                >
                  {s.title || "الموسم " + s.season_number}
                </button>
              ))}
            </div>

            {episodes === null ? (
              <div className="flex items-center justify-center py-8 text-muted-foreground">
                <Loader2 className="w-5 h-5 animate-spin" />
              </div>
            ) : episodes.length === 0 ? (
              <p className="text-sm text-muted-foreground py-6 text-center">لا توجد حلقات لهذا الموسم</p>
            ) : (
              <div className="grid sm:grid-cols-2 gap-2">
                {episodes.map((ep) => (
                  <button
                    key={ep.id}
                    onClick={() => setCurrentEp(ep)}
                    className={
                      "flex items-center justify-between gap-2 rounded-lg border px-4 py-3 text-sm text-right transition-colors " +
                      (currentEp && currentEp.id === ep.id
                        ? "border-primary bg-muted"
                        : "border-border hover:bg-muted")
                    }
                  >
                    <span className="flex items-center gap-2 truncate">
                      <span className="w-7 h-7 shrink-0 rounded-full bg-muted flex items-center justify-center text-xs font-bold text-muted-foreground">
                        {ep.number}
                      </span>
                      <span className="truncate">{ep.title}</span>
                    </span>
                    <Play className="w-4 h-4 text-primary shrink-0" />
                  </button>
                ))}
              </div>
            )}
          </>
        ) : (
          <p className="text-sm text-muted-foreground py-6 text-center">لا توجد مواسم لهذا المسلسل</p>
        )}
      </div>
    </div>
  );
}

const Center = ({ children }) => (
  <div className="min-h-screen flex flex-col items-center justify-center gap-2 text-muted-foreground" dir="rtl">
    {children}
  </div>
);