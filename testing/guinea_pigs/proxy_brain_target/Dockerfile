FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.0.3 pyjwt==2.8.0
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 5000
CMD ["python", "app.py"]
