# TOKIWA lab victim: a deliberately NON-vulnerable demo shop (canned responses only). Lab use only.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin victim
USER 10001
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/health', timeout=2)"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000", "--no-server-header"]
