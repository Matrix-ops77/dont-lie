# Dockerfile for the public Don't-Lie witness notary.
# A stdlib HTTP service that co-signs receipt hashes. No external deps.
FROM python:3.11-slim

WORKDIR /app

# Copy the package and the witness service entry point
COPY dontlie/ ./dontlie/
COPY pyproject.toml ./

# No pip install needed — the witness service uses only the stdlib
# and the cryptography library that's already in the package.
# (We use pip to install cryptography + dontlie itself.)
RUN pip install --no-cache-dir cryptography dontlie 2>/dev/null || \
    pip install --no-cache-dir cryptography && pip install --no-cache-dir -e .

# Run as a non-root user
RUN useradd -m -s /bin/bash witness
USER witness

# Default port. Override with --port.
EXPOSE 9099

# Persistent state: signing key + recent attestations.
# In production, mount a volume here so the key persists across restarts.
VOLUME ["/home/witness/.config/dontlie/witness"]

# Default: bind to 0.0.0.0 so the service is reachable from outside the container.
# Key dir is /home/witness/.config/dontlie/witness (volume-mounted).
ENTRYPOINT ["python3", "-m", "dontlie.witness_service", "--host", "0.0.0.0", "--port", "9099", "--key-dir", "/home/witness/.config/dontlie/witness"]
