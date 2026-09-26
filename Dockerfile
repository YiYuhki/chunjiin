FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[api]" \
    && useradd --system --no-create-home cdr

USER cdr
EXPOSE 8080
CMD ["uvicorn", "cdr.api:app", "--host", "0.0.0.0", "--port", "8080"]
