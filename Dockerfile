FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnotify-bin \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY packagealert/ packagealert/

RUN pip install --no-cache-dir -e .

RUN useradd -m packagealert
USER packagealert

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["package-alert"]
CMD ["daemon"]
