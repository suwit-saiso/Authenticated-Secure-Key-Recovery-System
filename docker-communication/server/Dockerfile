# server/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY server.py /app/server.py
RUN pip install flask

CMD ["python", "server.py"]
