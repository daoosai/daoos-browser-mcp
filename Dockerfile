FROM python:3.14-slim-trixie
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb x11vnc novnc ca-certificates fonts-liberation fonts-dejavu-core \
    libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libdbus-1-3 \
    libcups2 libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 \
    libgbm1 libxkbcommon0 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 \
    libxshmfence1 libatomic1 && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock /app/
RUN pip install --no-cache-dir -r requirements.lock
RUN apt-get update && apt-get install -y --no-install-recommends openbox && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml /app/
COPY browser /app/browser
COPY ops/chromium-sandbox.py /usr/local/bin/chromium-sandbox
ARG INSTALL_BROWSER=true
RUN if [ "$INSTALL_BROWSER" = true ]; then playwright install chromium --no-shell; fi
RUN useradd -m -u 10001 browser && mkdir -p /data /run/daoos-browser /ms-playwright && chown -R browser:browser /data /run/daoos-browser /ms-playwright
USER browser
EXPOSE 8000
CMD ["uvicorn", "browser.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--ws-max-size", "1048576"]
