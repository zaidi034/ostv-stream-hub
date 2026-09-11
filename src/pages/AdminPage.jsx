import React, { useEffect, useState } from "react";
import { base44 } from "@/api/base44Client";
import { Link } from "react-router-dom";
import { Loader2, ShieldAlert, Download, Library } from "lucide-react";
import ImportPanel from "@/components/admin/ImportPanel";
import ContentBrowser from "@/components/admin/ContentBrowser";

export default function AdminPage() {
  const [me, setMe] = useState(null);
  const [tab, setTab] = useState("import");

  useEffect(() => {
    base44.auth.me().then(setMe).catch(() => setMe({ role: "user" }));
  }, []);

  if (!me) {
    return (
      <div className="min-h-screen flex items-center justify-center text-muted-foreground" dir="rtl">
        <Loader2 className="w-6 h-6 animate-spin" />
      </div>
    );
  }

  if (me.role !== "admin") {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 text-muted-foreground px-4" dir="rtl">
        <ShieldAlert className="w-12 h-12 text-destructive" />
        <p className="font-medium">هذه الصفحة متاحة للمشرفين فقط</p>
        <Link to="/" className="text-primary text-sm hover:underline">العودة للرئيسية</Link>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <header className="sticky top-0 z-10 bg-background/90 backdrop-blur border-b border-border">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <Link to="/" className="text-xl font-bold font-heading text-primary">
            OS <span className="text-red-500">TV</span>
          </Link>
          <nav className="flex gap-1 p-1 rounded-xl bg-muted">
            <button
              onClick={() => setTab("import")}
              className={
                "flex items-center gap-1.5 px-3 sm:px-4 py-1.5 rounded-lg text-sm font-medium transition-colors " +
                (tab === "import" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")
              }
            >
              <Download className="w-4 h-4" /> <span className="hidden sm:inline">جلب المحتوى</span>
            </button>
            <button
              onClick={() => setTab("content")}
              className={
                "flex items-center gap-1.5 px-3 sm:px-4 py-1.5 rounded-lg text-sm font-medium transition-colors " +
                (tab === "content" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground")
              }
            >
              <Library className="w-4 h-4" /> <span className="hidden sm:inline">المحتوى المحفوظ</span>
            </button>
          </nav>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6">
        {tab === "import" ? <ImportPanel /> : <ContentBrowser />}
      </main>
    </div>
  );
}