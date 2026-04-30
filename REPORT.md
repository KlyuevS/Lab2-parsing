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

Также используется XML-каталог CWE MITRE для названий и описаний CWE.

Сложность: в CVE API не для всех записей есть CVSS, CPE и CWE. Код сохраняет то, что есть в API, без подстановки выдуманных значений. В текущем запуске получено 113 CVE; у 59 записей нет CVSS, у 113 записей нет CPE, у 59 записей нет CWE.

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

Проверка падает на пустых `cvss_list`, `cpe_list` или `cwe`, если в MITRE CVE API для конкретных CVE этих данных нет. В текущем запуске отсутствуют: CVSS у 59 записей, CPE у 113 записей, CWE у 59 записей. Чтобы проверка проходила полностью, нужно добавить внешний источник для недостающих данных или разрешить пустые списки в схеме.

## Задача 5

БД нормализована:

- `vulnerability` - основные данные CVE
- `cvss_score` - оценки CVSS
- `cpe` - справочник CPE
- `vulnerability_cpe` - связь CVE и CPE
- `cwe` - справочник CWE
- `vulnerability_cwe` - связь CVE и CWE

Файлы:

- `sql/schema.sql`
- `docker-compose.yml`
- `fill_db.py`
