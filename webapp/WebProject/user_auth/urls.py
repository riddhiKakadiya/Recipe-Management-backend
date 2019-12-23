from django.urls import path, re_path

from . import views
import logging
logger = logging.getLogger('__name__')
try:
    urlpatterns = [
        re_path(r'^$', views.signin, name='signin'),
        re_path(r'^v1/recipe/?$', views.createRecipe, name='createRecipe'),
        re_path(r'^v1/user/?$', views.registerPage, name='registerPage'),
        re_path(r'^v1/user/self/?$', views.getOrUpdateUser, name='getOrUpdateUser'),
        re_path(r'^v1/recipes/?$', views.getRecipes, name='getRecipe'),
        re_path(r'^v1/recipe/(?P<recipe_id>[0-9a-z-]+)/image$', views.addImageToRecipe, name='addImageToRecipe'),
        re_path(r'^v1/recipe/(?P<recipe_id>[0-9a-z-]+)/image/(?P<image_id>[0-9a-z-]+)$', views.getOrdeleteImageFromRecipe, name='getOrdeleteImageFromRecipe'),
        re_path(r'^v1/recipe/(?P<recipe_id>[0-9a-z-]+)$', views.recipeFromId, name='recipeFromId'),
        re_path(r'^v1/allrecipes/?$', views.getAllRecipes, name='getAllRecipe'),
        re_path(r'^.*/$', views.get404, name='get404'),
        re_path(r'pingtest/?$', views.pingTest, name='pingTest'),
        re_path(r'^metrics$', views.metrics, name='metrics')
    ]
          
except Exception as e:
    logger.debug("Something happened :\n %s", e)

