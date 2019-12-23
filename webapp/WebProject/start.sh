#!/bin/bash
# Start Gunicorn processes
touch /var/log/csye7374.log
chmod 777 -R /var/log/csye7374.log
python manage.py makemigrations user_auth
python manage.py migrate 
python manage.py migrate user_auth
echo Starting Gunicorn.
rm -rf multiproc-tmp

#Sharing this directory between workers
mkdir multiproc-tmp

export prometheus_multiproc_dir=multiproc-tmp
# guni
exec gunicorn -c gunicorn_conf.py WebProject.wsgi:application \
    --bind 0.0.0.0:8001 \
    --workers 3