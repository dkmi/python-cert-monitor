FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 cert-monitor \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin cert-monitor \
    && mkdir -p /app /etc/cert-monitor /var/lib/cert-monitor \
    && chown 10001:10001 /var/lib/cert-monitor
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY monitor.py ./
COPY tests/ ./tests/
USER 10001:10001
ENTRYPOINT ["python", "/app/monitor.py"]
