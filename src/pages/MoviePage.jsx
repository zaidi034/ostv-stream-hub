import React, { useEffect, useState } from "react";
import { base44 } from "@/api/base44Client";
import { Link, useParams } from "react-router-dom";
import { Image } from "@/components/ui/image";
import { ArrowRight, Download, Loader2, Star, Play } from "lucide-react";
import VideoPlayer from "@/components/VideoPlayer";

export default function MoviePage() {
  const { sourceId } = useParams();
  const [movie, setMovie] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [linkIdx, setLinkIdx] = useState(0);
  const [streamData, setStreamData] = useState(null);

  useEffect(() => {
    setMovie(null);
    setNotFound(false);
    setLinkIdx(0);
    base44.entities.Movie.filter({ source_id: Number(sourceId) }, null, 1).then((r) => {
      if (r && r.length) setMovie(r[0]);
      else setNotFound(true);
    });
  }, [sourceId]);

  useEffect(() => {
    setStreamData(null);
    base44.functions.invoke("oscarStream", { type: "movie", id: Number(sourceId) })
      .then((res) => { setStreamData(res.data || {}); setLinkIdx(0); })
      .catch(() => setStreamData({}));
  }, [sourceId]);

  if (notFound) {
    return (
      <Center>
        <p>الفيلم غير موجود</p>
        <Link to="/" className="text-primary text-sm hover:underline">العودة للرئيسية</Link>
      </Center>
    );
  }
  if (!movie) {
    return <Center><Loader2 className="w-6 h-6 animate-spin" /></Center>;
  }

  const links = (streamData && streamData.watch_links) || [];
  const dlLinks = (streamData && streamData.download_links) || [];

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <div className="max-w-4xl mx-auto px-4 py-6">
        <Link to="/" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-4">
          <ArrowRight className="w-4 h-4" /> العودة
        </Link>

        <div className="flex flex-col sm:flex-row gap-5 mb-6">
          <div className="w-32 sm:w-40 shrink-0 aspect-[2/3] rounded-xl overflow-hidden border border-border">
            {movie.poster_url && <Image src={movie.poster_url} alt={movie.title} className="w-full h-full object-cover" />}
          </div>
          <div className="flex-1">
            <h1 className="text-2xl font-bold">{movie.title}</h1>
            {movie.title_en && movie.title_en !== movie.title && (
              <p className="text-sm text-muted-foreground mt-1">{movie.title_en}</p>
            )}
            <div className="flex flex-wrap items-center gap-2 mt-3 text-sm text-muted-foreground">
              {movie.rating > 0 && (
                <span className="flex items-center gap-1 text-amber-400 font-medium">
                  <Star className="w-4 h-4" /> {Number(movie.rating).toFixed(1)}
                </span>
              )}
              {movie.year > 0 && <span>{movie.year}</span>}
              {movie.runtime > 0 && <span>{movie.runtime} دقيقة</span>}
              {movie.country && <span>{movie.country}</span>}
            </div>
            {movie.categories && movie.categories.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-3">
                {movie.categories.map((c) => (
                  <span key={c} className="text-xs bg-muted px-2 py-1 rounded-md">{c}</span>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="mb-6">
          {links.length > 1 && (
            <div className="flex flex-wrap gap-2 mb-3">
              {links.map((l, i) => (
                <button
                  key={i}
                  onClick={() => setLinkIdx(i)}
                  className={
                    "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium border " +
                    (i === linkIdx
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border text-muted-foreground hover:text-foreground")
                  }
                >
                  <Play className="w-3.5 h-3.5" />
                  {l.quality || l.name}
                </button>
              ))}
            </div>
          )}
          {streamData === null ? (
            <div className="w-full aspect-video bg-black rounded-xl flex items-center justify-center">
              <Loader2 className="w-6 h-6 animate-spin text-white" />
            </div>
          ) : (
            <VideoPlayer src={links[linkIdx]?.url} poster={movie.poster_url} />
          )}
        </div>

        {movie.story && (
          <section className="mb-6">
            <h2 className="text-lg font-bold mb-2">القصة</h2>
            <p className="text-sm text-muted-foreground leading-relaxed">{movie.story}</p>
          </section>
        )}

        {dlLinks.length > 0 && (
          <section>
            <h2 className="text-lg font-bold mb-2">روابط التحميل</h2>
            <div className="flex flex-col gap-2">
              {dlLinks.map((d, i) => (
                <a
                  key={i}
                  href={d.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-between gap-2 rounded-lg border border-border px-4 py-3 text-sm hover:bg-muted transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <Download className="w-4 h-4 text-primary" />
                    {d.quality || d.name}
                  </span>
                  {d.size && <span className="text-muted-foreground">{d.size}</span>}
                </a>
              ))}
            </div>
          </section>
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