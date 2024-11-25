# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the Pipfile and Pipfile.lock to the container
COPY Pipfile Pipfile.lock ./

# Install pipenv and project dependencies
RUN pip install pipenv && pipenv install --deploy --ignore-pipfile

# Copy the rest of the application code to the container
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the sync script
CMD ["pipenv", "run", "python", "sync.py"]