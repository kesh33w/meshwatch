FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    MW_DATA_DIR=/data MW_HOST=0.0.0.0 MW_PORT=8790

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY meshwatch ./meshwatch
RUN pip install . && useradd --uid 1000 --create-home meshwatch \
    && mkdir -p /data && chown meshwatch /data

USER meshwatch
VOLUME /data
EXPOSE 8790
HEALTHCHECK --interval=5m --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request,sys;urllib.request.urlopen('http://127.0.0.1:8790/healthz',timeout=4)" || exit 1
CMD ["meshwatch"]
