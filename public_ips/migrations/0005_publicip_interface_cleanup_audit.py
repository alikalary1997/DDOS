from django.db import migrations, models


def copy_interfaces(apps, schema_editor):
    PublicIP = apps.get_model("public_ips", "PublicIP")
    Device = apps.get_model("devices", "Device")
    alias = schema_editor.connection.alias
    for device_id, interface in Device.objects.using(alias).values_list("pk", "incoming_monitoring_interface"):
        PublicIP.objects.using(alias).filter(device_id=device_id).update(incoming_monitoring_interface=interface)


class Migration(migrations.Migration):
    dependencies = [("public_ips", "0004_alter_publicip_device_assignmentreview"), ("devices", "0003_device_incoming_monitoring_interface")]
    operations = [
        migrations.AddField(model_name="publicip", name="incoming_monitoring_interface", field=models.CharField(blank=True, max_length=255)),
        migrations.AddField(model_name="assignmentreview", name="cleanup_code", field=models.CharField(blank=True, max_length=40)),
        migrations.AddField(model_name="assignmentreview", name="cleanup_message", field=models.CharField(blank=True, max_length=255)),
        migrations.AddField(model_name="assignmentreview", name="requested_removal_ids", field=models.JSONField(default=list)),
        migrations.AddField(model_name="assignmentreview", name="removed_rule_ids", field=models.JSONField(default=list)),
        migrations.RunPython(copy_interfaces, migrations.RunPython.noop),
    ]
