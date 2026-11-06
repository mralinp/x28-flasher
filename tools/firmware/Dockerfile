FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends squashfs-tools mtd-utils liblzo2-dev build-essential && pip install --no-cache-dir ubi_reader && apt-get purge -y build-essential && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /analysis
