FROM python:3.6.3

ENV PYTHONUNBUFFERED 1
EXPOSE 5000

WORKDIR /usr/src/app

ADD requirements.txt /usr/src/app/
RUN pip install -r requirements.txt

ADD . /usr/src/app/
