FROM python:3.11-slim
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0
WORKDIR /app
COPY server.py /app/server.py
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9300"]
