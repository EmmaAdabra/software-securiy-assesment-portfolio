# Flask marketplace — containerised for Task E (SBOM and NIST SSDF compliance)
# Build: docker build -t exam-app:latest ./task-e
# Run:  docker run -p 5000:5000 exam-app:latest

# Pinned to a specific patch version — avoids silent upstream changes that could
# introduce vulnerabilities between builds.
FROM python:3.9.18-slim

WORKDIR /app

# Install dependencies before copying source code so Docker can cache this layer.
# A cache miss (e.g. changed requirements.txt) rebuilds only from this point down.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code.
COPY app.py schema.sql init_db.py ./
COPY static/ ./static/

# Create a non-root user and switch to it before the final command.
# Running as root inside a container is a NIST SSDF PW.6 violation and widens
# the blast radius if the application is exploited.
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 5000

# Initialise the database then start Flask.
CMD ["sh", "-c", "python init_db.py && python app.py"]