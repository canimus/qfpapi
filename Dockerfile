FROM python:3.6.3

EXPOSE 5000

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python setup.py
CMD ["python", "api.py"]
