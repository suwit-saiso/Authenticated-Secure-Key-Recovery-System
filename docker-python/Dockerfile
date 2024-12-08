FROM python:3.9-slim

# Install dependencies
RUN apt update && apt install -y curl

# Install Python dependencies
RUN pip install flask

# Copy application code to the container
WORKDIR /app
COPY ./app.py /app

# Expose port and run app
EXPOSE 5000
CMD ["python", "app.py"]
