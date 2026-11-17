# The link-preview app; the fake metadata service runs the stock python image (no build).
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 \
 && useradd --system --no-create-home lab
WORKDIR /app
COPY app.py ./
USER lab
EXPOSE 5000
CMD ["python", "app.py"]
