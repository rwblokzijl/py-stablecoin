# in the same Dockerfile
FROM python:3.7

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
        && mkdir Log

ADD stablecoin .

CMD [ "python", "./Client.py", "--guiPort", "80", "--localhost", "host.docker.internal", "--log", "logFile.html" ]
# CMD [ "python", "./Rendezvous-service.py", "--IP", "10.0.0.27", "--dummyNodes", "10" ]
