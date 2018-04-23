from django.conf.urls import url
from . import views  

print("login/urls.py.......")

urlpatterns = [
    #url(r'test$', views.test),   # This line has changed! Notice that urlpatterns is a list, the comma is in
    url(r'^$', views.index, name="index"),
    url(r'^dashboard$', views.dashboard),
    url(r'^wish_items/add_it/(\d+)$', views.add_item),
    url(r'^wish_items/create$', views.create_item),
    url(r'^wish_items/(\d+)$', views.display_item),
    url(r'^process$', views.process),
    url(r'^logout$',  views.logout),
    #url(r'^$', views.index),   # This line has changed! Notice that urlpatterns is a list, the comma is in
]                             # anticipation of all the routes that will be coming soon 
