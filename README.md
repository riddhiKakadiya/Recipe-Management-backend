# f19-t2-webapp-backend

# CSYE 7374 - Fall 2019

## Team Information

| Name | NEU ID | Email Address |
| --- | --- | --- |
| Jai Soni| 001822913|soni.j@husky.neu.edu |
| Riddhi Kakadiya| 001811354 | kamlesh.r@husky.neu.edu |
| Sreerag Mandakathil Sreenath| 001838559| mandakathil.s@husky.neu.edu|
| Vivek Dalal| 001430934 | dalal.vi@husky.neu.edu |



## Circle CI setup
### Required Environment variables
```bash
DOCKERHUB_USERNAME = <DOCKERHUB_USERNAME>
DOCKERHUB_PASS = <DOCKERHUB_PASS>
DOCKERHUB_IMAGE_NAME = <DOCKERHUB_USERNAME/TAG> 
```
DOCKERHUB_IMAGE_NAME eg. sreeragsreenath/f19-t2-webapp-backend

## Docker Commands

### Docker local build command for application 'f19-t2-webapp-backend' 
```bash
docker build -t <USER_NAME>/f19-t2-webapp-backend:latest .
```

### Docker run command
```bash
docker run -ti -p 8000:8000 <USER_NAME>/f19-t2-webapp-backend:latest 
```

### Docker push command
```bash
docker push <USER_NAME>/f19-t2-webapp-backend:latest
```

## Instructions to set up and run the application application 'f19-t2-webapp-backend' locally

## Install Dependencies
```bash
sudo dnf update -y
python3 -m pip install --user --upgrade pip
python3 -m pip install --user virtualenv
sudo dnf install mariadb mariadb-server mysql-connector-python3  -y

```

## Start MariaDB Service
```bash
sudo systemctl start mariadb.service
sudo systemctl enable mariadb.service
```

## Secure MYSQL installation
```bash
/usr/bin/mysql_secure_installation
```

## Create Database
```bash
mysql -u root -p<Password> <<EOF
CREATE DATABASE <Database>;
EOF
```

## Create Environment File

### File creation
```bash
mkdir ~/.django
vim ~/.django/.local_env
```

### ENV File Example
```bash
export DJANGO_PROFILE=local
export MARIADB_USERNAME=root
export MARIADB_PASSWORD=<Password>
export MARIADB_DATABASE=<Database>
export BACKEND_API=/v1/allrecipes
export BACKEND_HOST=localhost
export BACKEND_PORT=8001
echo "Local profile set"
```

## Sets to install python dependencies
```bash
sudo pip install virtualenv
sudo rm -rf djangoEnv
python3 -m venv djangoEnv
source djangoEnv/bin/activate
source ~/.django/.local_env
cd WebProject
pip3 install -r requirements.txt
```

## Migrate and run server commands
```bash
python manage.py makemigrations user_auth
python3 manage.py migrate
python3 manage.py runserver
```

## use your local host to run the application

## Please refer the Swagger documentation to hit the API end points
```bash
https://app.swaggerhub.com/apis-docs/csye7374-03/fall2019/assignment05#
```
