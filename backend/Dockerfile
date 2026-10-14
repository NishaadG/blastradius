FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY blastradius ./blastradius
COPY evals ./evals
ENV FALKOR_HOST=falkordb BR_DATA_DIR=/app/data
EXPOSE 8000
CMD ["uvicorn", "blastradius.api:app", "--host", "0.0.0.0", "--port", "8000"]
