FROM python:latest
ENV API_TOKEN=demo-token-value
RUN curl -fsSL https://install.example.com/setup.sh | sh
RUN apt-get update && apt-get install -y sudo
COPY . /app
CMD ["python", "/app/app.py"]
RUN curl -k https://models.example.com/weights.bin -o /models/weights.bin
COPY .env /app/.env
EXPOSE 22
RUN pip install awscli boto3
