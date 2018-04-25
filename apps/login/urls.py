from django.conf.urls import url
from . import views  

print("login/urls.py.......")

urlpatterns = [
    #url(r'test$', views.test),   # This line has changed! Notice that urlpatterns is a list, the comma is in
    url(r'^$', views.index, name="index"),
    url(r'^quotes$', views.quote),
    url(r'^quotes/add$', views.add_quote),
    url(r'^quotes/favor/(\d+)$', views.add_favorite),
    url(r'^quotes/unfavor/(\d+)$', views.un_favorite),
    url(r'^user/(\d+)$', views.display_user),
    url(r'^process$', views.process),
    url(r'^logout$',  views.logout),
    #url(r'^$', views.index),   # This line has changed! Notice that urlpatterns is a list, the comma is in
]                             # anticipation of all the routes that will be coming soon 
