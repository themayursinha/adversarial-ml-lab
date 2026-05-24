# Multi-stage build for maximum security and minimal size
# Using Chainguard Hardened Images (DHI)
# Chainguard images are cryptographically signed and verified.
# For strict digest pinning, add @sha256:... after each image tag.
# Dependabot monitors these images for updates weekly.

# --- Stage 1: Build & Install ---
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /app

# Install dependencies into a writable temporary prefix.
# This avoids writing to root-owned paths in Chainguard non-root images.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/tmp/install -r requirements.txt && \
    pip cache purge

# --- Stage 2: Final Hardened Image ---
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# Copy only the installed dependencies from the builder.
# Chainguard Python images default to uid/gid 65532 with home /home/nonroot.
COPY --from=builder /tmp/install /home/nonroot/.local
ENV PATH="/home/nonroot/.local/bin:${PATH}"

# Copy the application source code
COPY --chown=65532:65532 src/ ./src/
COPY --chown=65532:65532 app.py ./

# Environment configuration for Gradio
ENV GRADIO_SERVER_NAME="0.0.0.0"
ENV GRADIO_SERVER_PORT="7860"
ENV PYTHONUNBUFFERED=1

# Expose the application port
EXPOSE 7860

# Health check for security monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('localhost', 7860)); s.close()"]

# Use the secure entry point
ENTRYPOINT ["python", "app.py"]
