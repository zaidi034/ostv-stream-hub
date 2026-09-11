import React, { useEffect, useRef, useState } from "react";
import Hls from "hls.js";

export default function HlsPlayer({ src, onError }) {
  const videoRef = useRef(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !src) return;
    let hls;
    setError("");
    if (Hls.isSupported()) {
      hls = new Hls();
      hls.loadSource(src);
      hls.attachMedia(video);
      hls.on(Hls.Events.ERROR, (_event, data) => {
        if (data.fatal) {
          setError("تعذر تشغيل البث، جرّب جودة أخرى");
          onError && onError();
        }
      });
    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = src;
    } else {
      setError("المتصفح لا يدعم بث HLS");
    }
    return () => {
      if (hls) hls.destroy();
    };
  }, [src]);

  return (
    <div className="relative w-full aspect-video bg-black rounded-xl overflow-hidden">
      <video ref={videoRef} controls autoPlay playsInline className="w-full h-full" />
      {error && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-white bg-black/70">
          {error}
        </div>
      )}
    </div>
  );
}