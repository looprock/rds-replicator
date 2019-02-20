FROM alpine:3.8

COPY requirements.txt /tmp/

RUN \
  apk update \
  && apk add python3 py-pip python3-dev libffi-dev openssl-dev py3-openssl \
  && pip3 install -r /tmp/requirements.txt \
  && rm -rf /var/cache/apk/* \
  && mkdir -p /app

COPY *.py /app/
WORKDIR /app/
CMD /usr/bin/python3 ./replicate.py
