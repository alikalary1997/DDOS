from django.contrib.auth.views import LoginView
from django.urls import include, path

from . import views
from sensors import views as sensor_views

urlpatterns = [
    path("sensor-data/", sensor_views.fleet_data, name="device_sensor_data"),
    path("<int:device_id>/sensors/", include("sensors.urls")),
    path("<int:device_id>/raw-provisioning/", views.raw_provisioning_settings, name="device_raw_provisioning"),
    path("<int:device_id>/edit/", views.edit_device, name="device_edit"),
    path("<int:device_id>/delete/", views.delete_device, name="device_delete"),
    path("<int:device_id>/monitoring-interface/", views.save_monitoring_interface, name="device_monitoring_interface"),
    path("<int:device_id>/interfaces/", views.monitoring_interfaces, name="device_monitoring_interfaces"),
    path("<int:device_id>/test-connection/", views.test_connection, name="device_test_connection"),
    path("", views.inventory, name="devices"),
    path("add/", views.add_device, name="device_add"),
    path("login/", LoginView.as_view(template_name="devices/login.html", next_page="devices", extra_context={"active_page": "devices"}), name="device_login"),
]
