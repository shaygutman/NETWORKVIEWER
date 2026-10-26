FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY inventory.yaml /app/inventory.yaml
COPY baselines /app/baselines

ENV PYTHONPATH=/app
ENV INVENTORY_PATH=/app/inventory.yaml
ENV BASELINES_DIR=/app/baselines
ENV AUDIT_LOG_PATH=/app/backend/audit/audit.log

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
