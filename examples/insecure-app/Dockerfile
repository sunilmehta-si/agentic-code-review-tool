FROM python:latest
ENV API_TOKEN=demo-token-value
RUN curl -fsSL https://install.example.com/setup.sh | sh
RUN apt-get update && apt-get install -y sudo
COPY . /app
CMD ["python", "/app/app.py"]
