
#importing Django libraries
from django.shortcuts import render
from django.contrib.auth import authenticate
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils import timezone
import json
import re
import math
import base64
import time
import ast
from uuid import UUID
import datetime
from .models import *
import sys
import boto3
from django.conf import settings
import logging
from django_statsd.clients import statsd
from boto3.dynamodb.conditions import Key, Attr
import os
# import settings
from django.conf import settings
from elasticsearch import Elasticsearch
from prometheus_client import multiprocess
from prometheus_client import generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST, Gauge, Counter, Summary
import prometheus_client

def time_ms():
	return time.time()

# #--------------------------------------------------------------------------------
# Define Logger
# --------------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if settings.DEBUG == True:
	logger.setLevel("DEBUG")
else:
	logger.setLevel("INFO")


# #--------------------------------------------------------------------------------
# Initialize Metrics for Prometheus
# --------------------------------------------------------------------------------
HOSTNAME = os.environ.get('HOSTNAME')

api_common = Summary('api_common','Metrics for all api calls',['hostname'])
api_common_label = api_common.labels(HOSTNAME)
api_post_recipe_counter = Counter('api_post_recipe_counter','Counter for POST /v1/recipe/',['hostname'])

api_delete_recipe_counter = Counter('api_delete_recipe_counter','Counter for DELETE /v1/recipe/(recipe_id)',['hostname'])
api_put_recipe_counter = Counter('api_put_recipe_counter','Counter for PUT /v1/recipe/(recipe_id)',['hostname'])
api_get_user_counter = Counter('api_get_user_counter','Counter for GET /v1/user/self',['hostname'])
api_put_user_counter = Counter('api_put_user_counter','Counter for PUT /v1/user/self',['hostname'])
api_post_image_counter = Counter('api_post_image_counter','Counter for POST /v1/recipe/(recipe_id)/image',['hostname'])
api_delete_image_counter = Counter('api_delete_image_counter','Counter for DELETE /v1/recipe/(recipe_id)/image/(image_id)',['hostname'])
api_get_latest_recipe_counter = Counter('api_get_latest_recipe_counter','Counter for GET /v1/recipes',['hostname'])
api_get_recipe_counter = Counter('api_get_recipe_counter','Counter for GET /v1/recipe/(recipe_id)',['hostname'])
api_post_user_counter = Counter('api_post_user_counter','Counter for POST /v1/user/',['hostname'])
api_get_image_counter  = Counter('api_get_image_counter','Counter for GET /v1/recipe/(recipe_Id)/image/(image_Id)',['hostname'])
api_get_allrecipes_counter = Counter('api_get_allrecipes_counter','Counter for GET /v1/allrecipes',['hostname'])

api_es_index = Summary('api_es_index','Metrics for all api calls made to es',['hostname'])
api_es_index_label = api_es_index.labels(HOSTNAME)
api_es_delete = Summary('api_es_delete','Metrics for all api calls made to es to delete',['hostname'])
api_es_delete_label = api_es_delete.labels(HOSTNAME)

api_db_recipe_create = Summary('api_db_recipe_create','Summary for create recipe in db',['hostname'])
api_db_recipe_create_label = api_db_recipe_create.labels(HOSTNAME)
api_db_recipe_delete = Summary('api_db_recipe_delete','Summary for delete recipe in db',['hostname'])
api_db_recipe_delete_label = api_db_recipe_delete.labels(HOSTNAME)
api_db_recipe_update = Summary('api_db_recipe_update','Summary for update recipe in db',['hostname'])
api_db_recipe_update_label = api_db_recipe_update.labels(HOSTNAME)
api_db_recipe_read = Summary('api_db_recipe_read','Summary for read recipe in db',['hostname'])
api_db_recipe_read_label = api_db_recipe_read.labels(HOSTNAME)

api_db_user_create = Summary('api_db_user_create','Summary for create user in db',['hostname'])
api_db_user_create_label = api_db_user_create.labels(HOSTNAME)
api_db_user_delete = Summary('api_db_user_delete','Summary for delete user in db',['hostname'])
api_db_user_delete_label = api_db_user_delete.labels(HOSTNAME)
api_db_user_update = Summary('api_db_user_update','Summary for update user in db',['hostname'])
api_db_user_update_label = api_db_user_update.labels(HOSTNAME)
api_db_user_read = Summary('api_db_user_read','Summary for read user in db',['hostname'])
api_db_user_read_label = api_db_user_read.labels(HOSTNAME)

api_db_nutritioninfo_create = Summary('api_db_nutritioninfo_create','Summary for create nutrition_information in db',['hostname'])
api_db_nutritioninfo_create_label = api_db_nutritioninfo_create.labels(HOSTNAME)
api_db_nutritioninfo_delete = Summary('api_db_nutritioninfo_delete','Summary for delete nutrition_information in db',['hostname'])
api_db_nutritioninfo_delete_label = api_db_nutritioninfo_delete.labels(HOSTNAME)
api_db_nutritioninfo_update = Summary('api_db_nutritioninfo_update','Summary for update nutrition_information in db',['hostname'])
api_db_nutritioninfo_update_label = api_db_nutritioninfo_update.labels(HOSTNAME)
api_db_nutritioninfo_read = Summary('api_db_nutritioninfo_read','Summary for read nutrition_information in db',['hostname'])
api_db_nutritioninfo_read_label = api_db_nutritioninfo_read.labels(HOSTNAME)

api_db_image_create = Summary('api_db_image_create','Summary for create image in db',['hostname'])
api_db_image_create_label = api_db_image_create.labels(HOSTNAME)
api_db_image_delete = Summary('api_db_image_delete','Summary for delete image in db',['hostname'])
api_db_image_delete_label = api_db_image_delete.labels(HOSTNAME)
api_db_image_update = Summary('api_db_image_update','Summary for update image in db',['hostname'])
api_db_image_update_label = api_db_image_update.labels(HOSTNAME)
api_db_image_read = Summary('api_db_image_read','Summary for read image in db',['hostname'])
api_db_image_read_label = api_db_image_read.labels(HOSTNAME)
# #--------------------------------------------------------------------------------
# Initialize Elasticsearch
# --------------------------------------------------------------------------------
if (settings.ENV_DJANGO_PROFILE  == "local"):
	es = Elasticsearch(HOST="http://localhost",PORT=9200)
else:
	es = Elasticsearch('http://elasticsearch.default.svc.cluster.local:9200')
### es = Elasticsearch('http://elasticsearch.default.svc.cluster.local:9300')
@api_es_index_label.time()
def esIndex(index, doc_type,id, body):
	es.index(index=index, doc_type=doc_type,id=id, body=body)
	es.indices.refresh(index=index)
	# pass
@api_es_delete_label.time()
def esDelete(index, doc_type, id):
	es.delete(index=index, doc_type=doc_type,id=id)
	# pass

#--------------------------------------------------------------------------------
# Function definitions for reading, saving, updating and deleting
# --------------------------------------------------------------------------------
def save_image(file_to_upload,filename,	recipe):
	logger.debug("Save Image : settings.ENV_DJANGO_PROFILE : %s", settings.ENV_DJANGO_PROFILE)
	if (settings.ENV_DJANGO_PROFILE  == "local"):
		image = save_image_to_local(file_to_upload,filename,recipe)
	else:
		image = save_image_to_s3(file_to_upload=file_to_upload,filename=filename,acl="public-read",recipe=recipe)
	return image

def delete_image(image):
	logger.debug("Delete Image : settings.ENV_DJANGO_PROFILE : %s", settings.ENV_DJANGO_PROFILE)
	if (settings.ENV_DJANGO_PROFILE  == "local"):
		response = delete_image_from_local(image)
	else:
		response = delete_image_from_s3(image,acl="public-read")
	return response

def get_user_details(user):
	user_details = {}
	user_details['id'] = user.id
	user_details['first_name'] = user.user.first_name
	user_details['last_name'] = user.user.last_name
	user_details['email_address'] = user.user.email
	user_details['account_created'] = user.user.date_joined
	user_details['account_updated'] = user.account_updated
	return user_details

def get_nutrition_information(nutrition_information):
	nutrition_details = {}
	nutrition_details['calories'] = int(nutrition_information.calories)
	nutrition_details['cholesterol_in_mg'] = nutrition_information.cholesterol_in_mg
	nutrition_details['sodium_in_mg'] = nutrition_information.sodium_in_mg
	nutrition_details['carbohydrates_in_grams'] = nutrition_information.carbohydrates_in_grams
	nutrition_details['protein_in_grams'] = nutrition_information.protein_in_grams
	return nutrition_details

def get_recipe_details(recipe):
	recipe_details = {}
	try:
		start_time = time_ms()
		image = Image.objects.filter(recipe=recipe.id)[0]
		api_db_image_read_label.observe(time_ms()-start_time)
	except:
		image = None
	recipe_details['image'] = get_image_details(image)
	recipe_details['id'] = recipe.id
	recipe_details['created_ts'] = recipe.created_ts
	recipe_details['updated_ts'] = recipe.updated_ts
	recipe_details['cook_time_in_min'] = recipe.cook_time_in_min
	recipe_details['prep_time_in_min'] = recipe.prep_time_in_min
	recipe_details['total_time_in_min'] = recipe.total_time_in_min
	recipe_details['author_id'] = str(recipe.author_id)
	recipe_details['title'] = recipe.title
	recipe_details['cuisine'] = recipe.cuisine
	recipe_details['servings'] = recipe.servings
	if type(recipe.ingredients) ==type(''):
		recipe_details['ingredients'] = ast.literal_eval(recipe.ingredients)
	else:
		recipe_details['ingredients'] = recipe.ingredients
	if type(recipe.steps) ==type(''):
		recipe_details['steps'] = ast.literal_eval(recipe.steps)
	else:
		recipe_details['steps'] = recipe.steps
	recipe_details['nutrition_information'] = get_nutrition_information(recipe.nutrition_information)
	return recipe_details	

def get_image_details(image):
	image_details = {}
	if image:
		image_details['id'] = image.id
		image_details['url'] = image.url
	else:
		image_details['id'] = None
		image_details['url'] = None
	return image_details
#--------------------------------------------------------------------------------
# Function definitions for CRUD on local - default profile
# --------------------------------------------------------------------------------
def save_image_to_local(file_to_upload,filename,recipe):
	url = os.path.join(settings.MEDIA_ROOT, filename)
	meta={}
	meta['recipe_id'] = str(recipe.id)
	meta['user_id'] = str(recipe.author_id)
	meta['filename'] = str(filename)
	metadata = str(meta)
	image = Image(url = url,recipe=recipe ,metadata = metadata)
	image.save()

	filename, file_extension = os.path.splitext(filename)
	filename = str(image.id) + file_extension
	logger.info("Saving image to local : %s", filename)
	image.url = settings.MEDIA_URL+filename
	start_time = time_ms()
	image.save()
	api_db_image_create_label.observe(time_ms()-start_time) 
	logger.info("Image Saved")
	path = default_storage.save(filename, ContentFile(file_to_upload.read()))
	tmp_file = os.path.join(settings.MEDIA_ROOT, path)
	return image

def delete_image_from_local(image): 
	image_url = image.url
	filename=image_url[13:]
	logger.info("Deleting image from local : %s", filename)
	path = os.path.join(settings.MEDIA_ROOT, filename)
	default_storage.delete(path)
	start_time = time_ms()
	image.delete()
	api_db_image_delete_label.observe(time_ms()-start_time)  
	return JsonResponse({'message': 'image deleted from Local'}, status=200)

# def update_image_to_local(file_to_upload,filename,recipe,image):
# 	logger.info("Updating image in local : %s", filename)
# 	delete_image(image)
# 	new_image = save_image(file_to_upload,filename,recipe)	
# 	return new_image

#--------------------------------------------------------------------------------
# Function definitions for AWS S3 - dev profile
# -------------------------------------------------------------------------------

def save_image_to_s3(file_to_upload,filename,acl,recipe):
#Get AWS keys from local aws_credentials file
	logger.info("Saving image to S3")
	try:
		session = boto3.Session(
			aws_access_key_id=settings.ENV_AWS_ACCESS_KEY_ID,
			aws_secret_access_key=settings.ENV_AWS_SECRET_ACCESS_KEY
			)
		logger.info("S3 Saving session created successfully")
		bucketName = settings.ENV_BUCKET_NAME
		url = "dummy"
		metadata = {}
		image = Image(url = url,recipe=recipe,metadata = metadata)
		# image.save()	
		orignal_filename = filename
		filename, file_extension = os.path.splitext(filename)
		filename = str(image.id) + file_extension
		image.url = 'https://s3.amazonaws.com/'+bucketName+'/'+filename
		meta = {}
		meta['recipe_id'] = str(recipe)
		meta['user_id'] = str(recipe.author_id)
		meta['filename'] = str(orignal_filename)
		image.metadata = meta
		s3 = session.client('s3')
		s3.upload_fileobj(
			file_to_upload,
			bucketName,
			filename,
			ExtraArgs={
				"ACL": acl,
				"Metadata": meta
			}
		)
	except Exception as e:
		# This is a catch all exception, edit this part to fit your needs.
		logger.error("Something Happened: %s", e)
		logger.error(e)
		return e
	start_time = time_ms()
	image.save()
	api_db_image_create_label.observe(time_ms()-start_time) 
	logger.info("s3 image saved : %s", filename)
	return image

def delete_image_from_s3(image,acl):
	image_url=image.url
	extension=os.path.splitext(image_url)[1]
	filename=str(image.id)+extension
	try:
		session = boto3.Session(
			aws_access_key_id=settings.ENV_AWS_ACCESS_KEY_ID,
			aws_secret_access_key=settings.ENV_AWS_SECRET_ACCESS_KEY
			)
		bucketName = settings.ENV_BUCKET_NAME
		s3 = boto3.resource('s3')
		object=s3.Bucket(bucketName).Object(filename)
		object.delete()
		start_time = time_ms()
		image.delete()
		api_db_image_delete_label.observe(time_ms()-start_time) 
		logger.info("s3 image deleted : %s",filename)
		return JsonResponse({'message':'image deleted'}, status=204)
	except Exception as e:
		logger.error("Something Happened: %s", e)
		return e

#--------------------------------------------------------------------------------
# Function definitions
#--------------------------------------------------------------------------------

#Validating passwords
def validatePassword(password):
	message =""
	specialCharacters = ['$', '#', '@', '!', '*','_','-','&','^','+','%']
	if(len(password)==0):
		return JsonResponse({'message':'Password can\'t be blank'})

	if (8>len(password) or len(password)>=16):
		message+= 'The password must be between 8 and 16 characters. : '
	password_strength = {}
	if not re.search(r'[A-Z]', password):
		message+= "Password must contain one upppercase : "
	if not re.search(r'[a-z]', password):
		message+= "Password must contain one lowercase : "

	if not re.search(r'[0-9]', password):
		message+= "Password must contain one numeric : "

	if not any(c in specialCharacters for c in password):
		message+= "Password must contain one special character : "
	
	if (len(message)>0):
		return message
	else:
		return True

#Validing username
def validateUserName(username):
	valid = re.search(r'^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$',username)
	if valid:
		return True
	return "* please enter valid email ID *"


# Verify signed in user
def validateSignin(meta):
	if 'HTTP_AUTHORIZATION' in meta:
		auth = meta['HTTP_AUTHORIZATION'].split()
		if len(auth) == 2:
			if auth[0].lower() == "basic":
				authstring = base64.b64decode(auth[1]).decode("utf-8")
				username, password = authstring.split(':', 1)
				if not username and not password:
					return JsonResponse({'message': 'Error : User not logged, Please provide credentials'}, status=401)
				start_time = time_ms()
				user = authenticate(username=username, password=password)
				api_db_user_read_label.observe(time_ms()-start_time)
				if user is not None:

					return user					
	else:
		return False

def is_valid_uuid(uuid_to_test, version=4):
	"""
	Check if uuid_to_test is a valid UUID.

	Parameters
	----------
	uuid_to_test : str
	version : {1, 2, 3, 4}

	Returns
	-------
	`True` if uuid_to_test is a valid UUID, otherwise `False`.

	Examples
	--------
	>>> is_valid_uuid('c9bf9e57-1685-4c89-bafb-ff5af830be8a')
	True
	>>> is_valid_uuid('c9bf9e58')
	False
	"""
	try:
		uuid_obj = UUID(uuid_to_test, version=version)
		return True
	except:
		return False
#--------------------------------------------------------------------------------
# Views definitions
#--------------------------------------------------------------------------------	

@csrf_exempt
def signin(request):
	# statsd.incr('test2')

	# check if method is get
	if request.method == 'GET':
		if 'HTTP_AUTHORIZATION' in request.META:
			auth = request.META['HTTP_AUTHORIZATION'].split()
			if len(auth) == 2:
				if auth[0].lower() == "basic":
					authstring = base64.b64decode(auth[1]).decode("utf-8")
					username, password = authstring.split(':', 1)
					if not username and not password:
						return JsonResponse({'message': 'Error : User not logged, Please provide credentials'}, status=401)
					start_time = time_ms()
					user = authenticate(username=username, password=password)
					api_db_user_read_label.observe(time_ms()-start_time)
					if user is not None:
						current_time = time.ctime()
						return JsonResponse({"current time": current_time})
		# otherwise ask for authentification
		return JsonResponse({'message': 'Error : Incorrect user details entered'}, status=401)
	else:
		return JsonResponse({'Error': 'Please use a get method with user credentials'})
	if 'HTTP_AUTHORIZATION' in request.META:
		auth = request.META['HTTP_AUTHORIZATION'].split()
		if len(auth) == 2:
			if auth[0].lower() == "basic":
				authstring = base64.b64decode(auth[1]).decode("utf-8")
				username, password = authstring.split(':', 1)
				if not username and not password:
					return JsonResponse({'message':'Error : User not logged, Please provide credentials'}, status=401)
				start_time = time_ms()
				user = authenticate(username=username, password=password)
				api_db_user_read_label.observe(time_ms()-start_time)
				if user is not None:
					current_time = time.ctime()
					return JsonResponse({"current time": current_time})
	# otherwise ask for authentification
	return JsonResponse({'message': 'Error : Incorrect user details'}, status=401)


#--------------------------------------------------------------------------------------------------------------------------

@csrf_exempt
def pingTest(request):
	return JsonResponse({"message": " : Ping Test Successful"}, status=200)

@csrf_exempt
@api_common_label.time()
def registerPage(request):
	#check if method is post
	if request.method == 'POST':
		api_post_user_counter.labels(HOSTNAME).inc()
		#check if body is not empty
		if(request.body):
			received_json_data = json.loads(request.body.decode("utf-8"))
			try:
				
				firstname = received_json_data['first_name']
				lastname = received_json_data['last_name']
				username = received_json_data['email_address']
				password = received_json_data['password']
				if (firstname=="" or lastname=="" or username=="" or password == "" or username==None or password == None ):
					return JsonResponse({'message':'Please fill all fields'},status=400)
				# name_status = validateName(firstname,lastname)
				username_status = validateUserName(username)
				password_status = validatePassword(password)
				if (username_status == True and password_status == True):
					start_time = time_ms()
					if not User.objects.filter(username=username).exists():
						api_db_user_read_label.observe(time_ms()-start_time)
						account_updated = datetime.datetime.now()		
						user = User.objects.create_user(username = username, 
							email = username, 
							password = password, 
							first_name=firstname, 
							last_name=lastname, 
							date_joined=datetime.datetime.now())
						# user.is_staff= True
						user.save()
						# account_updated = datetime.datetime.now()

						myuser = MyUser(user=user, account_updated=account_updated)
						start_time = time_ms()
						myuser.save()
						api_db_user_create_label.observe(time_ms()-start_time)
						message = get_user_details(myuser)
						esIndex(index="users", doc_type='userDetails',id=myuser.id, body=message)
						logger.debug(str(message))
						return JsonResponse(message,status=201)
					else:
						return JsonResponse({'message': 'Error : Username exists'},status=400)
				else:
					if(password_status == True):
						return JsonResponse({"message" : username_status},status=400)	
					elif (username_status == True):
						return JsonResponse({"message" : password_status},status=400)
					else:
						return JsonResponse({'message':username_status + " " + password_status},status=400)
			except Exception as e:
				# print(e)
				logger.debug(e)
				return JsonResponse({'message':'Error : Please use a post method with parameters username and password to create user'},status=400)
	# If all the cases fail then return error message
	return JsonResponse({'message':'Error : Please use a post method with parameters username and password to create user'})

def getMultipleof5(num):
	return 5* math.ceil(num/5)

@csrf_exempt
@api_common_label.time()
def createRecipe(request):
	logger.debug("Request Method : %s /v1/recipe/", request.method)
	# Post method to create new recipes for authorized user
	if request.method == 'POST':
		api_post_recipe_counter.labels(HOSTNAME).inc()
		if (request.body):
			try:
				received_json_data = json.loads(request.body.decode("utf-8"))
				cook_time_in_min = getMultipleof5(int(received_json_data['cook_time_in_min']))
				prep_time_in_min = getMultipleof5(int(received_json_data['prep_time_in_min']))
				title = received_json_data['title']
				cuisine = received_json_data['cuisine']
				servings = received_json_data['servings']
				# ingredients = received_json_data['ingredients']
				ingredients = list(set(received_json_data['ingredients']))
				steps = received_json_data['steps']
				steps = sorted(steps, key = lambda i: (i['position']))
				nutrition_information_dict = received_json_data['nutrition_information']
				time_now = datetime.datetime.now()
				total_time_in_min = cook_time_in_min + prep_time_in_min
				user = validateSignin(request.META)
				
				if MyUser.objects.filter(user=user).exists():
					myuser = MyUser.objects.filter(user=user)[0]
					nutrition_information = NutritionInformation(calories = nutrition_information_dict['calories'],
						cholesterol_in_mg = nutrition_information_dict['cholesterol_in_mg'],
						sodium_in_mg = nutrition_information_dict['sodium_in_mg'],
						carbohydrates_in_grams = nutrition_information_dict['carbohydrates_in_grams'],
						protein_in_grams = nutrition_information_dict['protein_in_grams']
					)
					start_time = time_ms()
					nutrition_information.save()
					api_db_nutritioninfo_create_label.observe(time_ms()-start_time)
					recipe = Recipe(created_ts=time_now, 
						updated_ts=time_now,
						author_id=myuser, 
						cook_time_in_min=cook_time_in_min,
						prep_time_in_min=prep_time_in_min,
						total_time_in_min = total_time_in_min, 
						title = title,
						cuisine = cuisine,
						servings = servings,
						ingredients = ingredients,
						nutrition_information = nutrition_information,
						steps = steps
						)
					start_time = time_ms()
					recipe.save()
					api_db_recipe_create_label.observe(time_ms()-start_time)

					message = get_recipe_details(recipe)
					# message = {'message':'success'}
					esIndex(index="recipes", doc_type='Recipe',id=recipe.id, body=message)
					logger.info("Recipe Saved")
					return JsonResponse(message, status=200)
				else:
					logger.debug("Incorrect user details")
					return JsonResponse({'message': 'Error : User not authorized'}, status=401)
			except Exception as e:
				logger.debug("Incorrect request")
				logger.error(e)
				return JsonResponse({'message': """Error : Mandatory fields missing. Please refer to api documentation [https://app.swaggerhub.com/apis-docs/csye7374-03/fall2019/assignment05#/] """}, status=400)
	else:
		return JsonResponse({'message': """Error : Method request should be POST to create recipe. Please refer to api documentation [https://app.swaggerhub.com/apis-docs/csye7374-03/fall2019/assignment05#/] """}, status=400)
@csrf_exempt
@api_common_label.time()
def getRecipes(request):
	logger.debug("Request Method : %s /v1/recipes", request.method)
	try:
		api_get_latest_recipe_counter.labels(HOSTNAME).inc()
		if request.method == 'GET':
		
			try:
				start_time = time_ms()
				latest_recipe = Recipe.objects.latest('created_ts')
				api_db_recipe_read_label.observe(time_ms()-start_time)
			except Exception as e:
				logger.debug("No Recipe Found :")
				logger.error(e)
				# print("\nSomething happened : \n",e)
				return JsonResponse({'message': 'No Recipes present'}, status=204)
			if latest_recipe:
				message = get_recipe_details(latest_recipe)
				logger.info("Recipe served")
				return JsonResponse(message, status=200)
			else:
				return JsonResponse({"message":"No Recipes present"}, status=204)
		else:
			return JsonResponse({'message': 'Error : Use GET method to get latest recipe'}, status=400)
	except Exception as e:
			logger.error(e)
			# print("\nSomething happened : \n",e)
			return JsonResponse({'message': 'Bad Request'}, status=400)


@csrf_exempt
@api_common_label.time()
def getAllRecipes(request):
	logger.debug("Request Method : %s /v1/recipes", request.method)
	api_get_allrecipes_counter.labels(HOSTNAME).inc()
	if request.method == 'GET':
		try:
			start_time = time_ms()
			all_recipes = Recipe.objects.all().order_by('-updated_ts')
			api_db_recipe_read_label.observe(time_ms()-start_time)
			if len(all_recipes)>0:
				message_list = []
				for recipe in all_recipes:
					message_list.append(get_recipe_details(recipe))
				return JsonResponse(message_list, status=200,safe=False)
			else:
				return JsonResponse({"message":"No Recipes present"}, status=204)
		except Exception as e:
			logger.debug("Incorrect request")
			logger.error(e)
			# print("\nSomething happened : \n",e)
			return JsonResponse({'message': 'Error : in getting recipes'}, status=400)
	else:
		return JsonResponse({'message': 'Error : Use GET method to get latest recipe'}, status=400)
@csrf_exempt
@api_common_label.time()
def recipeFromId(request,recipe_id=""):
	logger.debug("Request Method : %s /v1/recipes", request.method)
	if recipe_id=='':
		return JsonResponse({"message":"No Recipes present with this ID. Please verify the ID"}, status=404)
	if request.method == 'GET':
		api_get_recipe_counter.labels(HOSTNAME).inc()
		if (is_valid_uuid(recipe_id)):
			try:
				start_time = time_ms()
				recipe = Recipe.objects.get(pk=recipe_id)
				api_db_recipe_read_label.observe(time_ms()-start_time)
				if recipe:
					message = get_recipe_details(recipe)
					logger.info("Recipe served")
					return JsonResponse(message, status=200)
				else:
					return JsonResponse({"message":"No Recipes present with this ID. Please verify the ID"}, status=404)
			except Exception as e:
				logger.debug("Incorrect request")
				logger.debug(e)
				# print("\nSomething happened : \n",e)
				return JsonResponse({'message': 'Error : in getting recipes'}, status=400)
		else:
			return JsonResponse({'message': 'No Recipes present with this ID. Please verify the ID'}, status=404)
	elif request.method == 'PUT':
		api_put_recipe_counter.labels(HOSTNAME).inc()
		user = validateSignin(request.META)
		if (is_valid_uuid(recipe_id)):
			if (user):
				myuser = MyUser.objects.filter(user=user)[0]
				try:
					recipe = Recipe.objects.get(pk=recipe_id)
				except Exception as e:
					logger.debug(e)
					return JsonResponse({"message":"No Recipes present with this ID"}, status=404)
				if(recipe) and (str(recipe.author_id)==str(myuser.id)):
					if (request.body):
						try:
							received_json_data = json.loads(request.body.decode("utf-8"))
							recipe.cook_time_in_min = getMultipleof5(int(received_json_data['cook_time_in_min']))
							recipe.prep_time_in_min = getMultipleof5(int(received_json_data['prep_time_in_min']))
							recipe.title = received_json_data['title']
							recipe.cuisine = received_json_data['cuisine']
							recipe.servings = received_json_data['servings']
							recipe.ingredients = list(set(received_json_data['ingredients']))
							steps = received_json_data['steps']
							recipe.steps = sorted(steps, key = lambda i: (i['position']))
							nutrition_information_dict = received_json_data['nutrition_information']
							nutrition_information = NutritionInformation.objects.get(pk=recipe.nutrition_information.id)
							nutrition_information.calories = nutrition_information_dict['calories']
							nutrition_information.cholesterol_in_mg = nutrition_information_dict['cholesterol_in_mg']
							nutrition_information.sodium_in_mg = nutrition_information_dict['sodium_in_mg']
							nutrition_information.carbohydrates_in_grams = nutrition_information_dict['carbohydrates_in_grams']
							nutrition_information.protein_in_grams = nutrition_information_dict['protein_in_grams']
							
							start_time = time_ms()
							nutrition_information.save()
							api_db_nutritioninfo_update_label.observe(time_ms()-start_time)
							
							recipe.nutrition_information = nutrition_information

							time_now = datetime.datetime.now()
							recipe.updated_ts = time_now
							recipe.total_time_in_min = recipe.cook_time_in_min + recipe.prep_time_in_min
							
							start_time = time_ms()
							recipe.save()
							api_db_recipe_update_label.observe(time_ms()-start_time)
														
							message = get_recipe_details(recipe)
							
							esIndex(index="recipes", doc_type='Recipe',id=recipe.id, body=message)
							
							logger.info("Recipe Updated")
							return JsonResponse(message, status=200)
						except Exception as e:
							logger.debug("Incorrect request")
							logger.debug(e)
							# print("\nSomething happened : \n",e)
							return JsonResponse({'message': """Error : Mandatory fields missing. Please refer to api documentation [https://app.swaggerhub.com/apis-docs/csye7374-03/fall2019/assignment05#/] """}, status=400)
					else:
						return JsonResponse({'message': """Error : Mandatory fields missing. Please refer to api documentation [https://app.swaggerhub.com/apis-docs/csye7374-03/fall2019/assignment05#/] """}, status=400)
				else:
					return JsonResponse({'message': 'Error : User unauthorized'}, status=401)
			else:
				logger.debug("User unauthorized")
				return JsonResponse({'message': 'Error : User unauthorized'}, status=401)	
		else:
			return JsonResponse({"message":"No Recipes present with this ID"}, status=404)
	
	elif request.method == 'DELETE':
		api_delete_recipe_counter.labels(HOSTNAME).inc()
		user = validateSignin(request.META)
		if (is_valid_uuid(recipe_id)):
			if (user):
				myuser = MyUser.objects.filter(user=user)[0]
				try:
					recipe = Recipe.objects.get(pk=recipe_id)
				except Exception as e:
					return JsonResponse({"message":"No Recipes present with this ID"}, status=404)
				if(recipe) and (str(recipe.author_id)==str(myuser.id)):
					try:
						start_time = time_ms()
						recipe.delete()
						api_db_recipe_delete_label.observe(time_ms()-start_time)
						esDelete(index="recipes", doc_type='Recipe',id=recipe_id)
						return JsonResponse({'message':'Recipe deleted'}, status=204)
					except Exception as e:
						logger.debug("Incorrect request")
						logger.debug(e)
						# print("\nSomething happened : \n",e)
						return JsonResponse({'message': 'Error : in deleting recipes'}, status=400)
				else:
					logger.debug("User unauthorized")
					return JsonResponse({'message': 'Error : User unauthorized'}, status=401)
			else:
				logger.debug("User unauthorized")
				return JsonResponse({'message': 'Error : User unauthorized'}, status=401)	
		else:
			return JsonResponse({"message":"No Recipes present with this ID"}, status=404)	
	else:
		return JsonResponse({'message': 'Error : Use GET, PUT or DELETE method'}, status=400)


@csrf_exempt
@api_common_label.time()
def getOrUpdateUser(request):
	if request.method == 'GET':
		api_get_user_counter.labels(HOSTNAME).inc()
		try:
			user = validateSignin(request.META)
			start_time = time_ms()
			myuser = MyUser.objects.filter(user=user)[0]
			api_db_user_read_label.observe(time_ms()-start_time)
			
			if (myuser):
				message = get_user_details(myuser)
				return JsonResponse(message, status=200)
		except Exception as e:
			logger.debug(e)
			return JsonResponse({'message': 'Bad Request'}, status=400)

	elif request.method == 'PUT':
		api_put_user_counter.labels(HOSTNAME).inc()
		try:
			user = validateSignin(request.META)
			my_user = MyUser.objects.filter(user=user)[0]
			if(my_user):
				if (request.body):
					received_json_data = json.loads(request.body.decode("utf-8"))					
					username = received_json_data['email_address']
					password = received_json_data['password']

					username_status = validateUserName(username)
					password_status = validatePassword(password)
					
					if not User.objects.filter(username=username).exists() or username==user.email:
						if (username_status == True and password_status == True):
							user.first_name = received_json_data['first_name']
							user.last_name = received_json_data['last_name']
							user.username = received_json_data['email_address']
							user.email = received_json_data['email_address']
							user.set_password(received_json_data['password'])
							user.save()
							my_user.user = user
							my_user.account_updated = datetime.datetime.now()
							start_time = time_ms()
							my_user.save()
							api_db_user_update_label.observe(time_ms()-start_time)
							message = get_user_details(myuser)

							esIndex(index="users", doc_type='userDetails',id=myuser.id, body=message)

							return JsonResponse(message, status=200)
						else:
							return JsonResponse({'message':username_status + " " + password_status},status=400)
					else:
						return JsonResponse({'Error' :'user exists'},status=400)
				else:
					return JsonResponse({'Error' :'use put method with required parameters'},status=400)
			else:
				return JsonResponse({'Error' :'user unauthorized'},status=401)
		except Exception as e:
			# print("\nSomething Happened:\n {}".format(e))
			logger.debug(e)
			return JsonResponse({'message': "user unauthorized"},status=401)
	else:
		return JsonResponse({'message': "Bad Request. Use GET or PUT method"},status=400)


@csrf_exempt
@api_common_label.time()
def addImageToRecipe(request,recipe_id=""):
	logger.debug("Request Method : %s /v1/recipe/recipe_id/image", request.method)
	try:
		# Post method to create new notes for authorized user
		if request.method == 'POST':
			api_post_image_counter.labels(HOSTNAME).inc()
			if (request.FILES):
				user = validateSignin(request.META)
				if(user):
					myuser = MyUser.objects.filter(user=user)[0]
					if(is_valid_uuid(recipe_id)):
						try:
							recipe = Recipe.objects.get(pk=recipe_id)
						except:
							logger.debug("Invalid recipe ID")
							return JsonResponse({'Error': 'Invalid recipe ID'}, status=400)
					else:
						logger.debug("Invalid recipe ID")
						return JsonResponse({'Error': 'Invalid recipe ID'}, status=400)
					if(recipe) and (str(recipe.author_id)==str(myuser.id)):
						# print("DEBUG recipe.image.url: ",recipe.image.url)
						try:
							image = Image.objects.filter(recipe=recipe.id)[0]
						except Exception as e:
							image=None
							logger.debug("No image present in recipe : {}".format(e))
							pass
						if image:
							return JsonResponse({'Error': 'Image exists for recipe. Please delete the current image and then add again'}, status=400)
						# if not recipe.image.url==None:
							# return JsonResponse({'Error': 'Image exists for recipe. Please delete the current image and then add again'}, status=400)
						file = request.FILES['image']
						image = save_image(file_to_upload=file, filename= file._get_name(), recipe=recipe)
						recipe.updated_ts = datetime.datetime.now()	
						start_time = time_ms()
						recipe.save()
						api_db_recipe_create_label.observe(time_ms()-start_time)
						message = get_image_details(image)

						message_recipe = get_recipe_details(recipe)
						esIndex(index="recipes", doc_type='Recipe',id=recipe.id, body=message_recipe)

						return JsonResponse(message, status=200)
					else:
						logger.debug("Incorrect user details")
						return JsonResponse({'message': 'Error : Invalid User Credentials'}, status=401)
				else:
					logger.debug("Incorrect user details")
					return JsonResponse({'message': 'Error : Invalid User Credentials'}, status=401)
			else:
				logger.debug("No Files Attached")
				return JsonResponse({'message': 'Error : Files not selected'}, status=400)
	except Exception as e:
		logger.error("Something Happened: %s", e)
		return JsonResponse({'Error': 'Bad Request'}, status=400)

@csrf_exempt
@api_common_label.time()
def getOrdeleteImageFromRecipe(request,recipe_id="",image_id=""):
	# Update method to update attachments for authorized user
	logger.debug("Request Method : %s /v1/recipe/recipe_id/image", request.method)
	try:
		# Delete method to delete attachments for authorized user
		if request.method == 'DELETE':
			api_delete_image_counter.labels(HOSTNAME).inc()
			user = validateSignin(request.META)
			if(user):
				myuser = MyUser.objects.filter(user=user)[0]
				if(is_valid_uuid(recipe_id)):
					try:
						recipe = Recipe.objects.get(pk=recipe_id)
					except:
						logger.debug("Invalid recipe ID")
						return JsonResponse({'Error': 'Invalid recipe ID'}, status=400)
				else:
					logger.debug("Invalid recipe ID")
					return JsonResponse({'Error': 'Invalid note ID'}, status=400)
				if(is_valid_uuid(image_id)):
					try:
						image = Image.objects.get(pk=image_id)
					except Exception as e:
						logger.debug("Invalid image ID")
						return JsonResponse({'Error': 'Invalid image ID'}, status=400)
				else:
					logger.debug("Invalid image ID")
					return JsonResponse({'Error': 'Invalid image ID'}, status=400)
				if(recipe) and (str(recipe.author_id)==str(myuser.id)):
					if(image.recipe.id == recipe.id):
						#Primary Logic for deleting attachments
						delete_image(image)
						recipe.updated_ts = datetime.datetime.now()
						recipe.save()

						message_recipe = get_recipe_details(recipe)
						esIndex(index="recipes", doc_type='Recipe',id=recipe.id, body=message_recipe)
						logger.info("Image Deleted")
						return JsonResponse({'message': 'Image Deleted'}, status=200)
					else:
						logger.debug("Invalid image ID")
						return JsonResponse({'Error': 'Invalid image ID'}, status=400)
				else:
					logger.debug("Incorrect user details")
					return JsonResponse({'message': 'Error : Invalid User Credentials'}, status=401)
			else:
				logger.debug("Incorrect user details")
				return JsonResponse({'message': 'Error : Invalid User Credentials'}, status=401)

		elif request.method == 'GET':
			api_get_image_counter.labels(HOSTNAME).inc()
			recipe=None
			image=None
			if(is_valid_uuid(recipe_id)):
				try:
					recipe = Recipe.objects.get(pk=recipe_id)
				except:
					logger.debug("Invalid recipe ID")
					return JsonResponse({'Error': 'Invalid recipe ID'}, status=404)
			else:
				logger.debug("Invalid recipe ID")
				return JsonResponse({'Error': 'Invalid recipe ID'}, status=400)
			if(is_valid_uuid(image_id)):
				try:
					start_time = time_ms()
					image = Image.objects.get(pk=image_id)
					api_db_image_read_label.observe(time_ms()-start_time)
				except:
					logger.debug("Invalid image ID")
					return JsonResponse({'Error': 'Invalid image ID'}, status=404)
			else:
				logger.debug("Invalid image ID")
				return JsonResponse({'Error': 'Invalid image ID'}, status=400)						
			if recipe and image:
				if image.recipe.id == recipe.id:
					message = get_image_details(image)
					return JsonResponse(message, status=200)
				else :
					return JsonResponse({'Error': 'Invalid image ID'}, status=404)
		logger.debug(" Request method should be GET (PUBLIC) or DELETE")
		return JsonResponse({'message': 'Error : Request method should be GET (PUBLIC) or DELETE'}, status=400)
	except Exception as e:
		logger.error("Something Happened: %s", e)
		return JsonResponse({'Error': 'Bad Request'}, status=400)

@csrf_exempt
def get404(request):
	return JsonResponse({'Error': 'Page not found'}, status=404)

# @csrf_exempt
# def metrics(request):
# 	return HttpResponse(
# 		prometheus_client.generate_latest(),
# 		content_type=CONTENT_TYPE_LATEST)

@csrf_exempt
def metrics(request):
	registry = CollectorRegistry()
	multiprocess.MultiProcessCollector(registry)
	data = generate_latest(registry)
	return HttpResponse(
		data,
		content_type=CONTENT_TYPE_LATEST)
