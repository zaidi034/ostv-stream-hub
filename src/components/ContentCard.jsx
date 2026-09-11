import React from "react";
import { Link } from "react-router-dom";
import { Image } from "@/components/ui/image";
import { Star } from "lucide-react";

export default function ContentCard({ to, posterUrl, title, year, rating }) {
  return (
    <Link to={to} className="group block w-36 sm:w-44 shrink-0">
      <div className="relative aspect-[2/3] rounded-xl overflow-hidden bg-muted border border-border">
        <Image
          src={posterUrl}
          alt={title}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
        />
        {rating > 0 && (
          <div className="absolute top-2 left-2 flex items-center gap-1 bg-black/70 text-amber-400 text-xs font-bold px-1.5 py-0.5 rounded-md">
            <Star className="w-3 h-3" />
            {Number(rating).toFixed(1)}
          </div>
        )}
      </div>
      <p className="mt-2 text-sm font-medium text-foreground truncate">{title}</p>
      {year ? <p className="text-xs text-muted-foreground">{year}</p> : null}
    </Link>
  );
}