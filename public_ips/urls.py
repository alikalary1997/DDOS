from django.urls import path
from . import views

urlpatterns = [
    path("<int:public_ip_id>/detection/<str:action>/", views.detection_control, name="public_ip_detection_control"),
    path("reviews/<int:review_id>/cleanup/", views.retry_cleanup, name="public_ip_cleanup"),
    path("<int:public_ip_id>/unassign/", views.unassign_public_ip, name="public_ip_unassign"),
    path("<int:public_ip_id>/edit/", views.edit_public_ip, name="public_ip_edit"),
    path("<int:public_ip_id>/delete/", views.delete_public_ip, name="public_ip_delete"),
    path("monitoring-data/", views.raw_monitoring_data, name="public_ip_monitoring_data"),
    path("monitoring/<str:scope>/<int:object_id>/<str:action>/", views.monitoring_control, name="public_ip_monitoring_control"),
    path("<int:public_ip_id>/provision/", views.retry_provisioning, name="public_ip_provision"),
    path("", views.inventory, name="public_ips"),
    path("add/", views.add_public_ip, name="public_ip_add"),
]
