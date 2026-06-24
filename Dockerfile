# Multi-stage build for maximum security and minimal size
# Using Chainguard Hardened Images (DHI)
# Chainguard images are cryptographically signed and verified.
# For strict digest pinning, add @sha256:... after each image tag.
# Dependabot monitors these images for updates weekly.

# --- Stage 1: Build & Install ---
FROM cgr.dev/chainguard/python:latest-dev@sha256:97ae4a8cba64560dc2279a5baa686409a2ca13e98d0fc21e24f7ec2f23deaff8 AS builder

WORKDIR /app

# Install dependencies into a writable temporary prefix.
# This avoids writing to root-owned paths in Chainguard non-root images.
COPY requirements-hashed.txt .
RUN pip install --no-cache-dir --prefix=/tmp/install --require-hashes -r requirements-hashed.txt && \
    pip cache purge

# --- Stage 2: Final Hardened Image ---
FROM cgr.dev/chainguard/python:latest@sha256:3b1c6334c5a216c52b4059f148fa5edbb0cacadd3e576eb0f2fc2a75bbbc2841

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
