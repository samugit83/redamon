# The Parts portal and its WAF (one process); the database is the stock postgres:16 image.
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 psycopg2-binary==2.9.10 \
 && useradd --system --no-create-home lab
WORKDIR /app
COPY app.py waf.py ./
USER lab
EXPOSE 5000
CMD ["python", "app.py"]
