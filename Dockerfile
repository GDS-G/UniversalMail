FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home mailapp && mkdir -p /app/data && chown 10001:10001 /app/data
COPY --chown=10001:10001 universalmail ./universalmail
COPY --chown=10001:10001 scripts/configure.py ./scripts/configure.py
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "universalmail.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
