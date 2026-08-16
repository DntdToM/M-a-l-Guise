FROM ubuntu:22.04

# Prevent interactive prompts during apt installations
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app/M-a-l-Guise

# Copy the entire project into the container
COPY . /app/M-a-l-Guise/

# Run the setup script to initialize the detector environment and apply patches
RUN bash setup.sh

# Set environment variables for matplotlib to run headlessly
ENV MPLCONFIGDIR=/tmp/matplotlib

# Default command: show help for batch_evaluate
CMD ["python3", "scripts/batch_evaluate.py", "--help"]
