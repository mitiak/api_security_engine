# Use the official Python 3.11 image as the base image
FROM python:3.11

# Set the working directory inside the container
WORKDIR /usr/app

# Copy the poetry.lock and pyproject.toml files to the container
COPY poetry.lock pyproject.toml /usr/app/

# Copy only the contents of the application code to the container
COPY api_security_engine /usr/app/api_security_engine

# Install poetry
RUN pip install poetry

# Configure Poetry to create virtualenvs
RUN poetry config virtualenvs.create false

# Install project dependencies using Poetry
RUN poetry install --no-interaction --no-ansi

# Expose port 9999
EXPOSE 9999

# Run the FastAPI application using uvicorn
CMD ["poetry", "run", "uvicorn", "api_security_engine.main:app", "--host", "0.0.0.0", "--port", "9999"]
