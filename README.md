# Лабораторная работа 2

Источник: <https://tomcat.apache.org/security-9.html>

## Установка

```bash
python3 -m pip install --user --break-system-packages -r requirements.txt
```

## Запуск

```bash
python3 main.py task1
python3 main.py task2
python3 main.py task3
python3 main.py task4
```

Или всё сразу:

```bash
python3 main.py all
```

Файлы результата:

- `result_task_1.json`
- `result_task_2.json`
- `result_task_3.xml`

Они добавлены в `.gitignore`, чтобы не выгружать результаты в GitHub.

## База данных

```bash
docker compose up -d
python3 fill_db.py
```

Схема таблиц: `sql/schema.sql`.

Подключение по умолчанию:

```text
postgresql://lab2:lab2@localhost:5432/lab2
```

Если нужно другое подключение:

```bash
DB_URL="postgresql://user:password@localhost:5432/db" python3 fill_db.py
```

