FROM python:3.7-alpine
WORKDIR /apps
ENV FLASK_APP files_app.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 81
COPY ./apps /apps
RUN apk add --no-cache gcc musl-dev linux-headers openssl-dev libffi-dev
RUN pip install -r requirements.txt
RUN pip install pyopenssl
RUN pip install flask-jwt-extended
CMD ["flask", "run", "--cert=project.crt", "--key=project.key"]