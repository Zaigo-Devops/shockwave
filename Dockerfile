# Use an official Python runtime as a parent image
FROM python:3.10.2

# Set the working directory to /app
WORKDIR /app

# Copy all the files from current directory to docker container's app directory
COPY . /app

# Wkhtmltopdf for generating default image
RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && apt-get -y install wkhtmltopdf

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000


# Define environment variable
ENV NAME World

# Run migrations for relevant database changes for the particular file commit.
# RUN yes | python3 manage.py makemigrations
# RUN python3 manage.py migrate

# Run app.py when the container launches
CMD python3 manage.py runserver 0.0.0.0:8000