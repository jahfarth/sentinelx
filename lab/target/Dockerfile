# SentinelX lab target — intentionally vulnerable box (LAB USE ONLY).
#
# Provides the Flask demo app on :5000 and a weak SSH account (labuser /
# lab12345) on :22 so the attack-lab scripts have a realistic target.
# Only built via `docker compose --profile lab up -d target`.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# sshd for the brute-force lab steps.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Weak lab-only credentials — never use this image outside the lab network.
RUN useradd -m -s /bin/bash labuser \
    && echo "labuser:lab12345" | chpasswd

EXPOSE 22 5000

ENTRYPOINT ["./entrypoint.sh"]
