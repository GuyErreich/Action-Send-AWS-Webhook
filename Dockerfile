FROM python:3.11-slim

WORKDIR /app

# Copy the requirements file first to leverage Docker's cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python script into the container
COPY  send_webhook.py .
RUN chmod +x send_webhook.py

# Set the default entrypoint
ENTRYPOINT ["/app/send_webhook.py"]
