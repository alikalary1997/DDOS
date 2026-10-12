from django.urls import include, path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("devices/", include("devices.urls")),
    path("public-ips/", include("public_ips.urls")),
    path("traffic-monitor/", views.traffic_monitor, name="traffic_monitor"),
    path("ddos-detection/", views.ddos_detection, name="ddos_detection"),
    path("alerts/", views.alerts, name="alerts"),
    path("reports/", views.reports, name="reports"),
    path("settings/", views.settings_page, name="settings"),
    path("monitoring-data/", views.monitoring_data, name="monitoring_data"),
    path("start-monitoring/", views.start_monitoring, name="start_monitoring"),
    path("stop-monitoring/", views.stop_monitoring, name="stop_monitoring"),
]