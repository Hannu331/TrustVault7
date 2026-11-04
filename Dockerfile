FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt . 
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV TV_DB=/data/trustvault.db TV_STORE=/data/blobs
CMD ["sh","-c","python -m scripts.seed && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
