# client/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY client.py /app/client.py
RUN pip install requests

CMD ["python", "client.py"]
