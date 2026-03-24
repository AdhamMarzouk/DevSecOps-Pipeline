# ── Deliberately old base image (triggers Trivy container scan) ───────────────
# python:3.8-slim reached end-of-life in October 2024.
# The image contains numerous unpatched OS-level CVEs.
FROM python:3.8-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create the files directory used by the /file endpoint
RUN mkdir -p /app/files && echo "Hello from the app container" > /app/files/readme.txt

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
