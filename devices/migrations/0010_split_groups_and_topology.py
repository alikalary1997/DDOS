"""Split the previous generic tree into two independent structures.

* Groups nest under Groups only: `Group.parent_group` becomes `Group.parent`, and any
  group that was parented by a device is lifted to top level (groups no longer have
  device parents).
* Devices get a topology chain (`topology_parent`, device -> device) separate from their
  Group tag (`group`). A device's previous `parent_group` becomes its Group tag; a device
  previously parented by another device keeps that as its topology parent.
"""
import django.db.models.deletion
from django.db import migrations, models


def snapshot_old_parents(apps, schema_editor):
    """Remember every device's old either/or parent before those fields are dropped."""
    Device = apps.get_model("devices", "Device")
    rows = list(Device.objects.values_list("id", "parent_group_id", "parent_device_id"))
    schema_editor.connection._netshield_old_parents = {
        pk: (group_id, device_id) for pk, group_id, device_id in rows}


def restore_new_parents(apps, schema_editor):
    """Write the snapshot into the two new, independent fields."""
    Device = apps.get_model("devices", "Device")
    snapshot = getattr(schema_editor.connection, "_netshield_old_parents", {})
    for pk, (group_id, device_id) in snapshot.items():
        fields = {}
        if group_id is not None:
            fields["group_id"] = group_id
        if device_id is not None:
            fields["topology_parent_id"] = device_id
        if fields:
            Device.objects.filter(pk=pk).update(**fields)
    schema_editor.connection._netshield_old_parents = {}


def lift_device_parented_groups(apps, schema_editor):
    """Groups no longer have device parents: lift any that do to top level."""
    Group = apps.get_model("devices", "Group")
    Group.objects.exclude(parent_device=None).update(parent_device=None)


class Migration(migrations.Migration):
    dependencies = [("devices", "0009_group_tree_parents")]

    operations = [
        # 1) Read the old parents into memory (fields still exist here).
        migrations.RunPython(snapshot_old_parents, migrations.RunPython.noop),
        migrations.RunPython(lift_device_parented_groups, migrations.RunPython.noop),

        # 2) Drop the superseded either/or fields and their shared constraint.
        migrations.RemoveConstraint(model_name="device", name="devices_device_single_parent"),
        migrations.RemoveField(model_name="device", name="parent_device"),
        migrations.RemoveField(model_name="device", name="parent_group"),

        # 3) Add the two independent device fields.
        migrations.AddField(
            model_name="device",
            name="group",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="devices", to="devices.group"),
        ),
        migrations.AddField(
            model_name="device",
            name="topology_parent",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="topology_children", to="devices.device"),
        ),

        # 4) Restore the data into the new fields.
        migrations.RunPython(restore_new_parents, migrations.RunPython.noop),

    ]
