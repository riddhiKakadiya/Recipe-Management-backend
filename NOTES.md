# Set up instructions

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
CREATE DATABASE csye7374_backend;
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
export MARIADB_PASSWORD=Csye2019
export MARIADB_DATABASE=csye7374_backend
echo "Local profile set"
```

## Sets to install python dependencies
```bash
sudo pip install virtualenv
sudo rm -rf djangoEnv
python3 -m venv djangoEnv
# Activating django env
source djangoEnv/bin/activate
# Activating environment variables
source ~/.django/.local_env
cd WebProject
# INstaling requirements
pip3 install -r requirements.txt
```
## Migrate and run server commands
```bash
python3 manage.py makemigrations user_auth
python3 manage.py migrate
python3 manage.py runserver
```

```bash
sudo pip install virtualenv
cd djangoEnv/ && source bin/activate 
virtualenv djangoEnv
mysql.server start
SELECT User FROM mysql.user;
```

### Docker commands
```bash
docker build -t sreeragsreenath/f19-t2-webapp-backend:latest .
```

```bash
docker push sreeragsreenath/f19-t2-webapp-backend:latest
```

### Elasticsearch python usage guide
<br>https://www.elastic.co/downloads/past-releases/elasticsearch-5-6-2
<br>https://www.elastic.co/downloads/past-releases/kibana-5-6-2
<br>https://www.youtube.com/watch?v=90BPstUKOMU&list=PLZyZs2Ld646MBucOp122TSI3wSpUCwcsd
<br>Best references : 
<br>https://github.com/vivdalal/Vivek_Dalal_IOTLab_project
<br>https://medium.com/the-andela-way/getting-started-with-elasticsearch-python-part-two-1c0c9d1117ea

### Kibana API's
```bash
GET _cluster/health
GET _cat/indices?v
GET users/userDetails/_search?size=1000
GET users/userDetails/1190b31d-4a1e-4718-a6b6-d40f8c863dfd
GET recipes/Recipe/_search?size=1000
GET recipes/Recipe/d55acec3-bb6c-4762-a9ec-4c7bdcaf70c3
```

Dummy commit for building circle CI