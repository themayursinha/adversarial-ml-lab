# Multi-stage build for maximum security and minimal size
# Using Chainguard Hardened Images (DHI)

# --- Stage 1: Build & Install ---
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /app

# Install dependencies into a dedicated path
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: Final Hardened Image ---
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# Copy only the installed dependencies from the builder
COPY --from=builder /install /home/python/.local
ENV PATH="/home/python/.local/bin:${PATH}"
ENV PYTHONPATH="/home/python/.local/lib/python3.12/site-packages:${PYTHONPATH}"

# Copy the application source code
COPY --chown=python:python src/ ./src/
COPY --chown=python:python app.py ./

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
