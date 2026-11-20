import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import ruCommon from "@/locales/ru/common.json";

void i18n.use(initReactI18next).init({
  lng: "ru",
  fallbackLng: "ru",
  defaultNS: "common",
  resources: {
    ru: {
      common: ruCommon,
    },
  },
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
