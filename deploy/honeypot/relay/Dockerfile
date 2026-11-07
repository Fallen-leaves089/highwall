FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY relay.py /app/relay.py

USER 0:0
ENTRYPOINT ["python", "-I", "-S", "-u", "/app/relay.py"]
