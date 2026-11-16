"""Replace the flat Group tag with a generic fleet tree.

DeviceGroup becomes Group (keeping its primary keys, so every device keeps its group),
and both groups and devices gain an either/or parent reference so either kind can be
nested under either kind. Existing groups become top-level nodes.

The old flat `Device.group` is bridged first (copied into the new `parent_group`), and only
then dropped, so no existing device/group assignment can be lost.
"""
import django.db.models.deletion
from django.db import migrations, models


def copy_group_into_tree(apps, schema_editor):
    """Copy each device's flat group into its new tree parent (1:1, before the old field goes)."""
    Device = apps.get_model("devices", "Device")
    for device in Device.objects.exclude(group__isnull=True).only("id", "group_id"):
        Device.objects.filter(pk=device.pk).update(parent_group_id=device.group_id)


def restore_flat_group(apps, schema_editor):
    Device = apps.get_model("devices", "Device")
    for device in Device.objects.exclude(parent_group__isnull=True).only("id", "parent_group_id"):
        Device.objects.filter(pk=device.pk).update(group_id=device.parent_group_id)


class Migration(migrations.Migration):
    dependencies = [("devices", "0008_devicegroup_device_group")]

    operations = [
        # 1) Keep the rows: rename the model rather than dropping and recreating it.
        migrations.RenameModel(old_name="DeviceGroup", new_name="Group"),
        migrations.AlterModelOptions(name="group", options={"ordering": ["name", "pk"]}),

        # 2) Either/or parent on a group: another group, or a device.
        migrations.AddField(
            model_name="group",
            name="parent_group",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                    related_name="child_groups", to="devices.group"),
        ),
        migrations.AddField(
            model_name="group",
            name="parent_device",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                    related_name="child_groups", to="devices.device"),
        ),
        migrations.AddConstraint(
            model_name="group",
            constraint=models.CheckConstraint(
                condition=models.Q(parent_group__isnull=True) | models.Q(parent_device__isnull=True),
                name="devices_group_single_parent"),
        ),

        # 3) Same either/or parent on a device: a group, or another device.
        migrations.AddField(
            model_name="device",
            name="parent_group",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="child_devices", to="devices.group"),
        ),
        migrations.AddField(
            model_name="device",
            name="parent_device",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="child_devices", to="devices.device"),
        ),
        migrations.AddConstraint(
            model_name="device",
            constraint=models.CheckConstraint(
                condition=models.Q(parent_group__isnull=True) | models.Q(parent_device__isnull=True),
                name="devices_device_single_parent"),
        ),

        # 4) Bridge the data while the old field still exists.
        migrations.RunPython(copy_group_into_tree, migrations.RunPython.noop),

        # 5) Drop the superseded flat field: one tree, no parallel system.
        migrations.RemoveField(model_name="device", name="group"),
    ]
