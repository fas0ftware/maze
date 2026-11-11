# Maze honeypot - container image.
#   docker build -t maze .
#   docker run --rm -p 127.0.0.1:5000:5000 --read-only --tmpfs /tmp \
#     -e MAZE_REAL_PASSWORD_HASH='$argon2id$...' -v maze-data:/data maze
#
# Stage 1 builds the hardened C engine; stage 2 only carries the runtime.

FROM python:3.12-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config libsodium-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY core/ core/
RUN make -C core && make -C core test

FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsodium23 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin maze \
 && mkdir -p /data && chown maze:maze /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
COPY config/ config/
COPY --from=build /src/core/build/libmaze.so core/build/libmaze.so

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MAZE_HOST=0.0.0.0 \
    MAZE_PORT=5000 \
    MAZE_DB_PATH=/data/maze.db
USER maze
VOLUME ["/data"]
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:5000/', timeout=2)" || exit 1
CMD ["python", "-m", "app"]
