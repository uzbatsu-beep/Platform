import { useTranslation } from "react-i18next";

export function App() {
  const { t } = useTranslation("common");

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
      <section className="max-w-xl border border-slate-800 bg-slate-900 rounded-lg p-6 space-y-2">
        <h1 className="text-xl font-semibold tracking-tight">{t("app.name")}</h1>
        <p className="text-sm text-slate-300">{t("app.subtitle")}</p>
        <p className="text-xs text-slate-400">{t("app.bootstrapStatus")}</p>
      </section>
    </main>
  );
}
