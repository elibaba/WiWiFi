# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# tcpdump is required for Scapy's packet sniffing capabilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the application port
EXPOSE 8000

# Run the application in simulation mode by default
CMD ["python3", "backend/main.py"]
