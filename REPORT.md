# Отчёт

## Задача 1

Использованы `requests` и `beautifulsoup4`. Скрипт читает страницу Apache Tomcat 9, проходит по блокам `Fixed in Apache Tomcat 9.x`, достаёт CVE, дату релиза и ссылку на блок страницы.

Пример результата:

```json
{
    "ID": "CVE-2026-34500",
    "vendor_release_date": "2026-04-03",
    "vendor_release_url": "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.117"
}
```

## Задача 2

Использован MITRE CVE API:

```text
https://cveawg.mitre.org/api/cve/<CVE-ID>
```

Также используется MITRE CWE API:

```text
https://cwe-api.mitre.org/api/v1/cwe/weakness/<ID>
```

Ускорение: CVE и CWE запрашиваются параллельно через `ThreadPoolExecutor`, ответы MITRE API сохраняются в `.cache/`, поэтому повторный запуск идёт значительно быстрее.

CPE: в MITRE CVE API для Tomcat нет готового поля `cpes` для большинства записей, поэтому CPE формируется из API-полей `affected.vendor` и `affected.product` в формате CPE 2.3. Например: `cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*`.

CWE: теперь собираются CWE не только из CNA-контейнера, но и из ADP-контейнеров CVE API. Например, для `CVE-2026-34500` находится `CWE-287`, а название и описание берутся через MITRE CWE API.

Сложность: в CVE API не для всех старых записей есть CVSS и CWE. Код сохраняет то, что есть в MITRE API, без подстановки выдуманных значений. В текущем запуске получено 113 CVE; CPE есть у всех записей, у 59 записей нет CVSS, у 47 записей нет CWE.

## Задача 3

Использован стандартный модуль `xml.etree.ElementTree`. JSON из задачи 2 сохраняется в `result_task_3.xml` с нужной вложенностью:

- `cvss_list` -> `cvss`
- `cpe_list` -> `cpe`
- `cwe` -> `cwe`

## Задача 4

Схема находится в `json_schema.json`. Проверка запускается так:

```bash
python3 main.py task4
```

Проверка падает на пустых `cvss_list` или `cwe`, если в MITRE CVE API для конкретных CVE этих данных нет. В текущем запуске отсутствуют: CVSS у 59 записей, CWE у 47 записей. CPE теперь есть у всех записей. Чтобы проверка проходила полностью, нужно либо использовать дополнительный разрешённый источник данных для недостающих CVSS/CWE, либо разрешить пустые списки в схеме для случаев, где MITRE API не содержит этих данных.

## Задача 5

БД нормализована:

- `vulnerability` - основные данные CVE
- `cvss_score` - оценки CVSS
- `cpe` - справочник CPE
- `vulnerability_cpe` - связь CVE и CPE
- `cwe` - справочник CWE
- `vulnerability_cwe` - связь CVE и CWE

Замечание по ключам: текущая схема использует integer PK (`bigserial`). CVE-ID и CWE-ID перенесены в строковое поле `name` с `unique`, потому что это внешние идентификаторы, а внутренние связи БД удобнее и стабильнее строить по числовым ключам.

Для CWE выбран MITRE CWE API, а не скачивание XML-файла, потому что замечание преподавателя было использовать API; XML-загрузка удалена.

Файлы:

- `sql/schema.sql`
- `docker-compose.yml`
- `fill_db.py`
