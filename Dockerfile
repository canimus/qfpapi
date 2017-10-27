FROM python:3.6.3

ENV PYTHONUNBUFFERED 1
EXPOSE 5000

WORKDIR /usr/src/app

ADD requirements.txt ./
RUN pip install -r requirements.txt

ADD . .
RUN python setup.py
CMD ["python", "api.py"]
