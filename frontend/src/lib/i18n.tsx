/**
 * Minimal i18n. Japanese is the default UI language; English is available from the top bar.
 *
 * Usage:
 *   const t = useT();
 *   t("common.save")                     // global dictionary below
 *   const L = useLocal({ ja: { title: "アラート" }, en: { title: "Alerts" } });  // page-local strings
 *   L.title
 */
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from "react";

export type Lang = "ja" | "en";

const STORAGE_KEY = "tokiwa.lang";

const common = {
  ja: {
    "common.save": "保存",
    "common.cancel": "キャンセル",
    "common.delete": "削除",
    "common.edit": "編集",
    "common.create": "作成",
    "common.search": "検索",
    "common.refresh": "更新",
    "common.loading": "読み込み中…",
    "common.empty": "データがありません",
    "common.error": "エラーが発生しました",
    "common.close": "閉じる",
    "common.confirm": "確認",
    "common.approve": "承認",
    "common.reject": "却下",
    "common.status": "状態",
    "common.severity": "重大度",
    "common.source": "送信元",
    "common.time": "時刻",
    "common.details": "詳細",
    "common.actions": "操作",
    "common.all": "すべて",
    "common.logout": "ログアウト",
    "severity.info": "情報",
    "severity.low": "低",
    "severity.medium": "中",
    "severity.high": "高",
    "severity.critical": "緊急",
    "nav.section.monitor": "監視",
    "nav.section.investigate": "調査",
    "nav.section.intel": "インテリジェンス",
    "nav.section.respond": "対処",
    "nav.section.system": "システム",
  },
  en: {
    "common.save": "Save",
    "common.cancel": "Cancel",
    "common.delete": "Delete",
    "common.edit": "Edit",
    "common.create": "Create",
    "common.search": "Search",
    "common.refresh": "Refresh",
    "common.loading": "Loading…",
    "common.empty": "No data",
    "common.error": "Something went wrong",
    "common.close": "Close",
    "common.confirm": "Confirm",
    "common.approve": "Approve",
    "common.reject": "Reject",
    "common.status": "Status",
    "common.severity": "Severity",
    "common.source": "Source",
    "common.time": "Time",
    "common.details": "Details",
    "common.actions": "Actions",
    "common.all": "All",
    "common.logout": "Log out",
    "severity.info": "Info",
    "severity.low": "Low",
    "severity.medium": "Medium",
    "severity.high": "High",
    "severity.critical": "Critical",
    "nav.section.monitor": "Monitor",
    "nav.section.investigate": "Investigate",
    "nav.section.intel": "Intelligence",
    "nav.section.respond": "Respond",
    "nav.section.system": "System",
  },
} as const;

export type CommonKey = keyof (typeof common)["ja"];

let currentLang: Lang = (() => {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "en" ? "en" : "ja";
  } catch {
    return "ja";
  }
})();

export function getLang(): Lang {
  return currentLang;
}

type Ctx = { lang: Lang; setLang: (l: Lang) => void };
const LangContext = createContext<Ctx>({ lang: currentLang, setLang: () => {} });

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(currentLang);
  const setLang = useCallback((l: Lang) => {
    currentLang = l;
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* ignore */
    }
    document.documentElement.lang = l;
    setLangState(l);
  }, []);
  const value = useMemo(() => ({ lang, setLang }), [lang, setLang]);
  return <LangContext.Provider value={value}>{children}</LangContext.Provider>;
}

export function useLang(): Ctx {
  return useContext(LangContext);
}

export function useT(): (key: CommonKey) => string {
  const { lang } = useLang();
  return useCallback((key: CommonKey) => common[lang][key] ?? key, [lang]);
}

export function useLocal<T extends Record<string, string>>(dict: { ja: T; en: T }): T {
  const { lang } = useLang();
  return dict[lang];
}

/** Pick a localized label object ({ja, en}) */
export function useLabel(): (label: { ja: string; en: string }) => string {
  const { lang } = useLang();
  return useCallback((label: { ja: string; en: string }) => label[lang], [lang]);
}
