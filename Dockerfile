FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
COPY main.py fill_db.py json_schema.json ./

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py", "all"]
