
FROM python:3

WORKDIR /app
COPY requirements.txt influx.py /app/
RUN pip install -r /app/requirements.txt \
 && chmod 755 influx.py

CMD ["python3", "-u", "/app/influx.py"]
