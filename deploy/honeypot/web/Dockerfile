FROM python:3.15-alpine

WORKDIR /app
COPY decoy.py /app/decoy.py

USER 65532:65532
EXPOSE 8080

CMD ["python", "/app/decoy.py"]
