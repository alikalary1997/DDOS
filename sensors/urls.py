from django.urls import path
from . import views

urlpatterns = [
    path('', views.inventory, name='device_sensors'),
    path('profile/', views.profile, name='sensor_profile'),
    path('discover/', views.discover, name='sensor_discover'),
    path('detect/', views.detect, name='sensor_detect'),
    path('add/', views.add, name='sensor_add'),
    path('data/', views.data, name='sensor_data'),
    path('<int:sensor_id>/edit/', views.edit, name='sensor_edit'),
    path('<int:sensor_id>/<str:action>/', views.control, name='sensor_control'),
]
