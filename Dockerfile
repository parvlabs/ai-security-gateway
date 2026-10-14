FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specifications
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy gateway application source and configuration
COPY app/ ./app/
COPY config/ ./config/

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV GATEWAY_HOST=0.0.0.0
ENV GATEWAY_PORT=8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
