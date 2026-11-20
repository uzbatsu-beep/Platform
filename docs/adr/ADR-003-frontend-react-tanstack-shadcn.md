# ADR-003: Стек Frontend (React 19, TypeScript, Vite 8.x, TanStack, shadcn/ui) и i18n

- **Статус:** Утверждено (Decision Gate NEON)
- **Дата:** 2026-11-20

## Решение
Использовать React 19 + TypeScript + [Vite 8.x](https://vite.dev/blog/announcing-vite8) + TanStack (Router, Query, [Table](https://tanstack.com/table/latest), [Virtual](https://tanstack.com/virtual/latest/docs/framework/react/react-virtual) с `useFlushSync: false`) + [shadcn/ui](https://ui.shadcn.com/docs/installation/tanstack-router) + Tailwind CSS в виде статического SPA без Node.js в production.
- Все шрифты, иконки и ассеты поставляются локально (air-gapped).
- С первого дня внедряется полноценный i18n-слой (основной язык MVP — русский, EN — в следующей фазе).
