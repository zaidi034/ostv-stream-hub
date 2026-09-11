import React from "react";

export default function VideoPlayer({ src, poster }) {
  if (!src) {
    return (
      <div className="w-full aspect-video bg-black rounded-xl flex items-center justify-center text-muted-foreground text-sm">
        لا توجد روابط مشاهدة متاحة
      </div>
    );
  }
  return (
    <video
      src={src}
      poster={poster}
      controls
      autoPlay
      playsInline
      className="w-full aspect-video bg-black rounded-xl"
    />
  );
}