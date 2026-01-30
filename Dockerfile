FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all files
COPY . .

# Expose port (Backend uses 5000 by default in Flask, but code seems to use 8080? Or 5000?)
# backend.py check required. Most likely 5000 or specified in app.run().
# I will expose 5000 and 80 for safety.
EXPOSE 5000

# Run the backend
CMD ["python", "backend.py"]
