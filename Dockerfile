FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /WebProject
WORKDIR /WebProject
COPY webapp/WebProject/requirements.txt /WebProject
RUN pip install -r requirements.txt
COPY webapp/WebProject/. /WebProject
EXPOSE 8001
CMD ["./start.sh"]