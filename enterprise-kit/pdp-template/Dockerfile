FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY pdp_server.py .
COPY rules.json .

EXPOSE 9000
CMD ["python", "pdp_server.py", "--port", "9000", "--config", "rules.json"]
