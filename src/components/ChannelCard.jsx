import React from "react";
import { Link } from "react-router-dom";
import { Image } from "@/components/ui/image";

export default function ChannelCard({ sourceId, name, logoUrl, groupName }) {
  return (
    <Link
      to={"/channel/" + sourceId}
      className="group flex flex-col items-center gap-2 w-28 sm:w-32 shrink-0"
    >
      <div className="w-full aspect-square rounded-xl overflow-hidden bg-muted border border-border flex items-center justify-center">
        {logoUrl ? (
          <Image
            src={logoUrl}
            alt={name}
            fittingType="fit"
            className="w-full h-full object-contain p-2"
          />
        ) : (
          <span className="text-muted-foreground text-xs">قناة</span>
        )}
      </div>
      <p className="text-xs font-medium text-foreground text-center leading-tight line-clamp-2">
        {name}
      </p>
      {groupName && <p className="text-[10px] text-muted-foreground truncate w-full text-center">{groupName}</p>}
    </Link>
  );
}