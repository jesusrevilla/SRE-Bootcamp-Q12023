FROM python:3-alpine

# Add your instructions to dockerize the application
# App must run on port 8000

WORKDIR /src

COPY . /src

RUN pip --no-cache-dir install -r requirements.txt

CMD ["python", "api.py"]