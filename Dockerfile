FROM tiangolo/uwsgi-nginx-flask:python3.9

COPY ./requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt
COPY ./app /app
COPY ./utils /app/utils
