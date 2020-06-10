
FROM python:3

WORKDIR /app
COPY . .
RUN pip install -r /app/requirements.txt \
 && chmod 755 influx.py

CMD ["python3", "/app/influx.py"]
