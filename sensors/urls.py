from django.urls import path
from . import views

urlpatterns = [
    path('', views.inventory, name='device_sensors'),
    path('profile/', views.profile, name='sensor_profile'),
    path('discover/', views.discover, name='sensor_discover'),
    path('detect/', views.detect, name='sensor_detect'),
    path('add/', views.add, name='sensor_add'),
    path('ddos-settings/', views.ddos_settings, name='device_ddos_settings'),
    path('ddos-protection/', views.ddos_protection, name='device_ddos_protection'),
    path('ddos-protection/toggle/', views.ddos_protection_toggle, name='device_ddos_protection_toggle'),
    path('data/', views.data, name='sensor_data'),
    path('<int:sensor_id>/edit/', views.edit, name='sensor_edit'),
    path('<int:sensor_id>/<str:action>/', views.control, name='sensor_control'),
]
