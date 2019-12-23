import uuid
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator
import datetime

class MyUser(models.Model):
	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
	account_updated = models.DateTimeField()
	def __str__(self):
		return (str(self.id))

class NutritionInformation(models.Model):
	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	calories = models.IntegerField(default=0)
	cholesterol_in_mg = models.FloatField(default=0.0)
	sodium_in_mg = models.FloatField(default=0.0)
	carbohydrates_in_grams = models.FloatField(default=0.0)
	protein_in_grams = models.FloatField(default=0.0)
	def __str__(self):
		return (str(self.id))

class Recipe(models.Model):
	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	created_ts = models.DateTimeField()
	updated_ts = models.DateTimeField()
	author_id = models.ForeignKey(MyUser, on_delete=models.DO_NOTHING)
	cook_time_in_min = models.IntegerField(default=5,validators=[MinValueValidator(5)])
	prep_time_in_min = models.IntegerField(default=5)
	total_time_in_min = models.IntegerField(default=10,validators=[MinValueValidator(10)])
	title = models.CharField(max_length=500)
	cuisine = models.CharField(max_length=500)
	servings = models.IntegerField(default=1, validators=[MinValueValidator(1), MaxValueValidator(5)])
	ingredients = models.CharField(max_length=500)
	steps = models.CharField(default=None,max_length=1000)
	nutrition_information = models.ForeignKey(NutritionInformation, on_delete=models.CASCADE,)
	# image = models.ForeignKey(Image, on_delete=models.CASCADE,default=None)
	def __str__(self):
		return (str(self.id))

class Image(models.Model):
	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	url = models.CharField(max_length=1000,default=None)
	metadata = models.CharField(max_length=5000, default = "")
	recipe = models.ForeignKey(Recipe, on_delete=models.CASCADE)
	def __str__(self):
		return (str(self.id))


# class Steps(models.Model):
# 	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
# 	recipe_information = models.ForeignKey(Recipe, on_delete=models.CASCADE)
# 	position = models.IntegerField(default=0)
# 	items = models.CharField(max_length=500)
# 	def __str__(self):
# 		return (str(self.id))