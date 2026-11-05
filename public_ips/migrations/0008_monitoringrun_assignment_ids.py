from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("public_ips", "0007_publicip_detection_enabled")]

    operations = [
        migrations.AddField(
            model_name="monitoringrun",
            name="assignment_ids",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
