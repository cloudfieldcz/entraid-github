# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Add the Pipfile and Pipfile.lock into the container at /app
COPY Pipfile ./Pipfile
COPY Pipfile.lock ./Pipfile.lock

# Set up and activate a virtual environment
RUN python -m venv ./venv
ENV PATH="/app/venv/bin:$PATH"

# Install pipenv
RUN pip install pipenv

# Install any needed packages specified in Pipfile
RUN python -m pipenv install --system --deploy

# Copy the rest of the application code to the container
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the sync script
CMD ["pipenv", "run", "python", "sync.py"]