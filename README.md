# VAmPI DevSecOps — учебный стенд безопасной разработки

Это форк [VAmPI](https://github.com/erev0s/VAmPI) — намеренно уязвимого REST API на Flask. К нему добавлены база Postgres, веб-клиент на JavaScript и полный DevSecOps-контур, который целиком работает на одном ноутбуке: GitLab CI, сканеры безопасности, staging-сервер, DAST и телеметрия.

Репозиторий — решение тестового задания ([ASSIGNMENT.md](ASSIGNMENT.md)). Официальная записка для проверяющих — [NOTE.md](NOTE.md) (на английском). Этот файл — краткое описание на русском.

> **Внимание.** Приложение уязвимо намеренно. Не публикуйте его в сети: все порты стенда слушают только `127.0.0.1`.

## Что внутри

| Часть | Что делает | Где лежит |
|---|---|---|
| Приложение | API на Flask, Postgres, веб-клиент на nginx | `app.py`, `api_views/`, `models/`, `frontend/` |
| GitLab CE + Runner | хранит код, собирает образы, запускает пайплайн | `scripts/gitlab-up.sh`, `.gitlab-ci.yml` |
| Гейты безопасности | Semgrep, Gitleaks, Syft + Grype, Trivy | `.gitlab-ci.yml`, `.semgrep/`, `ci/` |
| Staging-сервер | ВМ в VirtualBox, куда пайплайн выкладывает приложение | `scripts/staging-up.sh`, `staging/` |
| DAST | OWASP ZAP сканирует развёрнутое приложение | `ci/dast_session.py`, `ci/zap_gate.py` |
| Телеметрия | OpenSearch + Dashboards: находки, события пайплайна, логи | `scripts/telemetry-up.sh`, `telemetry/`, `tools/nwtelemetry/` |
| Отчёт трендов | CLI, который сравнивает прогоны между собой | `scripts/trend` |

## Как устроен пайплайн

```
test  →  build  →  scan  →  deploy  →  dast  →  report
```

| Стадия | Джобы | Что происходит |
|---|---|---|
| `test` | `unit-tests`, `frontend-check`, `telemetry-tests`, `sast-semgrep`, `secrets-gitleaks`, `sbom-syft`, `sca-grype` | тесты и гейты по исходному коду |
| `build` | `build-api`, `build-frontend` | сборка двух образов и отправка в registry GitLab |
| `scan` | `scan-image-api`, `scan-image-frontend` | Trivy: уязвимости, секреты и ошибки Dockerfile |
| `deploy` | `deploy-staging` | выкладка образов на ВМ по SSH |
| `dast` | `dast-zap-baseline`, `dast-zap-api` | пассивный обход клиента и активный скан API |
| `report` | `telemetry-report` | отправка всех отчётов в OpenSearch и отчёт трендов |

Гейт — это джоб, который сохраняет полный отчёт сканера и падает, если найдено что-то выше порога. Пороги и их обоснование описаны в [docs/SECURITY_GATES.md](docs/SECURITY_GATES.md).

**Пайплайн заканчивается статусом `failed`, и это ожидаемо.** Гейты падают на уязвимостях, которые намеренно оставлены неисправленными (список — в [NOTE.md](NOTE.md), §9). Тесты, сборка, деплой и оба DAST-гейта зелёные.

## Требования

- 16 ГБ оперативной памяти.
- Docker Desktop (на его ВМ нужно около 10 ГБ).
- VirtualBox 7 и Vagrant 2.4.
- Bash с утилитами `git`, `curl`, `openssl`, `ssh` и `python3`. На Windows подходит Git Bash.
- Одна строка в файле hosts: `127.0.0.1 gitlab.northwind.test`.

Стенд проверен только на Windows 11 с Docker Desktop (WSL 2) и Git Bash.

## Быстрый старт

### Только приложение

```bash
docker compose up --build
curl localhost:5000/createdb      # создать и наполнить базу
```

После этого веб-клиент доступен на http://localhost:8088, а API — на http://localhost:5000.

### Весь стенд

Команды выполняются из корня репозитория именно в таком порядке:

```bash
scripts/gitlab-up.sh         # GitLab, registry, runner, проект, первый пайплайн
scripts/telemetry-up.sh      # OpenSearch и Dashboards
scripts/staging-up.sh        # staging-ВМ
scripts/gitlab-up.sh --run   # полный пайплайн с деплоем, DAST и телеметрией
scripts/trend --since 7d     # отчёт трендов
```

Первый запуск занимает 25–30 минут, повторный — несколько минут. Все скрипты можно запускать повторно: каждый шаг сначала проверяет, сделан ли он уже.

Подробная инструкция, зависимости между частями и разбор неполадок — в [docs/RUNBOOK.ru.md](docs/RUNBOOK.ru.md).

## Адреса

| Что | Адрес | Вход |
|---|---|---|
| GitLab | http://gitlab.northwind.test:8929 | `root`, пароль в `.local/root-password` |
| Dashboards | http://127.0.0.1:5601 | `analyst`, пароль в `.local/telemetry/analyst-password` |
| OpenSearch | https://127.0.0.1:9200 | свой CA: `.local/telemetry/certs/ca.pem` |
| Приложение на staging | http://127.0.0.1:18088 | — |
| API на staging | http://127.0.0.1:15000 | — |

Все пароли и ключи генерируются скриптами и хранятся в каталоге `.local/`, который не попадает в git.

## Что исправлено и что оставлено

**Исправлено** (подтверждено сравнением прогонов):

- SQL-инъекция в поиске пользователя (PT-01);
- смена чужого пароля (PT-03);
- отказ в обслуживании через регулярное выражение (PT-11);
- запуск контейнеров от root;
- устаревший образ nginx и отсутствие защитных HTTP-заголовков;
- уязвимые версии jQuery, lodash и moment.

**Оставлено** (на этом и падают гейты):

- XSS в веб-клиенте (PT-07);
- слабый ключ подписи JWT и `debug=True`;
- устаревшие Flask и PyJWT;
- уязвимые системные пакеты в базовых образах;
- синтетический ключ AWS в истории git.

Номера PT-NN — это пункты отчёта о пентесте: [docs/PENTEST_SUMMARY.md](docs/PENTEST_SUMMARY.md).

## Документация

| Документ | О чём | Язык |
|---|---|---|
| [NOTE.md](NOTE.md) | записка к сдаче: что сделано, решения, ограничения | английский |
| [docs/RUNBOOK.ru.md](docs/RUNBOOK.ru.md) | как всё работает, что от чего зависит, как поднимать и чинить | русский |
| [docs/SECURITY_GATES.md](docs/SECURITY_GATES.md) | гейты, пороги, подавления, работа без сети | английский |
| [docs/STAGING.md](docs/STAGING.md) | staging-ВМ, деплой, DAST | английский |
| [docs/TELEMETRY.md](docs/TELEMETRY.md) | телеметрия, права доступа, отчёт трендов | английский |
| [docs/BASELINE.md](docs/BASELINE.md) | чем форк отличается от исходного VAmPI | английский |
| [docs/VAMPI_README.md](docs/VAMPI_README.md) | исходный README проекта VAmPI | английский |

## Лицензия

Как и исходный VAmPI — см. [LICENSE](LICENSE).
