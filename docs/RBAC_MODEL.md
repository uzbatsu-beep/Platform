# NEON Scoped RBAC и Организационная структура (PR-04)

## 1. Модель прав и скоупов
- Формат права: `<module>:<resource>:<action>` (`core:user:read`, `core:user:manage`, `core:role:read`, `core:role:manage`, `core:organization:read`, `core:organization:manage`, `core:department:manage`, `core:location:manage`).
- Полномочия никогда не выдаются по имени роли (например, `"admin"`), а только по явным `PermissionGrant` из БД.
- Иерархия областей: **`Global` ⊇ `Site` ⊇ `Department`**; **`Own`** — изолированная область только на собственные ресурсы пользователя.

## 2. Критические инварианты безопасности
1. **Deny-by-default** и серверная проверка исключительно в `application`-слое (`AuthorizationService`, `OrganizationService`).
2. `AuthContext` формируется только сервером по проверенной сессии (клиентские заголовки/JSON не принимаются).
3. **Запрет эскалации при делегировании:** инициатор не может создать роль или назначить роль с правами/скоупом, выходящими за пределы его собственных грантов.
4. **SQL-фильтрация:** списки пользователей, площадок и подразделений фильтруются на уровне SQL-запросов репозитория.
5. **Защита последнего администратора:** транзакционная проверка в `deactivate_user_checked` и `revoke_assignment_checked` (с advisory lock в PostgreSQL и single-writer транзакцией в SQLite) запрещает деактивацию или лишение прав последнего активного глобального администратора.
6. **Организационная структура:** `Organization → Site → Department → Location` с проверкой принадлежности `Department` к `Site`, защитой от циклов, запретом архивирования узлов с активными связями и строгим разделением HTTP `412 Precondition Failed` (`If-Match`) vs `409 Conflict` (`expected_row_version` / доменные конфликты, ADR-011).

## PR-04.1 Hardening: Устранение IDOR и политика multi-scope
- Методы `AuthorizationService::deactivate_user` и `AuthorizationService::revoke_assignment` больше **не принимают** клиентский `target_scope`.
- **Политика `deactivate_user`:** внутри DB-транзакции загружаются все активные scope целевого пользователя. Вызывающий обязан иметь `core:user:manage`, покрывающий **каждый** активный scope цели (или `Scope::Global`, если у цели нет активных назначений). Деактивация и отзыв всех сессий выполняются в одной транзакции с защитой последнего глобального администратора.
- **Политика `revoke_assignment`:** внутри DB-транзакции загружается фактическая запись назначения (`scope`, `role_id`) и права роли. Вызывающий обязан иметь `core:role:manage` и **все** права этой роли, покрывающие фактический `scope` назначения.
