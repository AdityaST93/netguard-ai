FROM python:3.11-slim

WORKDIR /app

# System deps (libpcap needed for optional scapy live-capture support)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate demo data and train the baseline model at build time so the
# container is immediately usable.
RUN python ml/generate_synthetic_data.py --rows 20000 --out data/sample_traffic.csv \
    && python ml/train_model.py

ENV HOST=0.0.0.0 \
    PORT=5000 \
    DEBUG=False

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
