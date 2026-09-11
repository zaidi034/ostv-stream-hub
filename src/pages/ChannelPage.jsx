import React, { useEffect, useState } from "react";
import { base44 } from "@/api/base44Client";
import { Link, useParams } from "react-router-dom";
import { Image } from "@/components/ui/image";
import { ArrowRight, Loader2, Radio } from "lucide-react";
import HlsPlayer from "@/components/HlsPlayer";

export default function ChannelPage() {
  const { sourceId } = useParams();
  const [channel, setChannel] = useState(null);
  const [notFound, setNotFound] = useState(false);
  const [streamIdx, setStreamIdx] = useState(0);
  const [streams, setStreams] = useState(null);

  useEffect(() => {
    setChannel(null);
    setNotFound(false);
    setStreamIdx(0);
    setStreams(null);
    base44.entities.Channel.filter({ source_id: Number(sourceId) }, null, 1).then((r) => {
      if (r && r.length) setChannel(r[0]);
      else setNotFound(true);
    });
    base44.functions.invoke("oscarStream", { type: "channel", id: Number(sourceId) })
      .then((res) => { setStreams((res.data && res.data.streams) || []); setStreamIdx(0); })
      .catch(() => setStreams([]));
  }, [sourceId]);

  if (notFound) {
    return (
      <Center>
        <p>القناة غير موجودة</p>
        <Link to="/" className="text-primary text-sm hover:underline">العودة للرئيسية</Link>
      </Center>
    );
  }
  if (!channel) {
    return <Center><Loader2 className="w-6 h-6 animate-spin" /></Center>;
  }

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <div className="max-w-4xl mx-auto px-4 py-6">
        <Link to="/" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-4">
          <ArrowRight className="w-4 h-4" /> العودة
        </Link>

        <div className="flex items-center gap-4 mb-5">
          <div className="w-16 h-16 rounded-xl overflow-hidden bg-muted border border-border flex items-center justify-center shrink-0">
            {channel.logo_url ? (
              <Image src={channel.logo_url} alt={channel.name} fittingType="fit" className="w-full h-full object-contain p-1.5" />
            ) : (
              <Radio className="w-6 h-6 text-muted-foreground" />
            )}
          </div>
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              {channel.name}
              <span className="flex items-center gap-1 text-[10px] font-bold text-red-500">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" /> مباشر
              </span>
            </h1>
            <p className="text-sm text-muted-foreground">
              {[channel.group_name, channel.category, channel.country].filter(Boolean).join(" · ")}
            </p>
          </div>
        </div>

        {streams === null ? (
          <div className="w-full aspect-video bg-black rounded-xl flex items-center justify-center">
            <Loader2 className="w-6 h-6 animate-spin text-white" />
          </div>
        ) : streams.length === 0 ? (
          <div className="w-full aspect-video bg-black rounded-xl flex items-center justify-center text-muted-foreground text-sm">
            لا توجد روابط بث متاحة
          </div>
        ) : (
          <>
            {streams.length > 1 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {streams.map((s, i) => (
                  <button
                    key={i}
                    onClick={() => setStreamIdx(i)}
                    className={
                      "px-3 py-1.5 rounded-lg text-sm font-medium border " +
                      (i === streamIdx
                        ? "bg-primary text-primary-foreground border-primary"
                        : "border-border text-muted-foreground hover:text-foreground")
                    }
                  >
                    {s.quality || s.name}
                  </button>
                ))}
              </div>
            )}
            <HlsPlayer
              src={streams[streamIdx].url}
              onError={() => {
                // stream failed — automatically move to the next quality
                if (streamIdx < streams.length - 1) setStreamIdx(streamIdx + 1);
              }}
            />
          </>
        )}

        {channel.description && (
          <p className="text-sm text-muted-foreground leading-relaxed mt-5 whitespace-pre-line">
            {channel.description}
          </p>
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