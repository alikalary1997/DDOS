"""Groups nest under groups only: rename the self-parent field and drop the device parent.

`SeparateDatabaseAndState` is used because SQLite cannot drop a column that a CHECK
constraint still references, so the table is rebuilt. A plain RenameField would also
resolve the old field name against the current model state (which already uses `parent`).
"""
from django.db import migrations

REBUILD = """
CREATE TABLE devices_group_new (
  id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
  name varchar(120) NOT NULL UNIQUE,
  parent_id bigint NULL REFERENCES devices_group (id) DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO devices_group_new (id, name, parent_id)
  SELECT id, name, parent_group_id FROM devices_group;
DROP TABLE devices_group;
ALTER TABLE devices_group_new RENAME TO devices_group;
CREATE INDEX devices_group_parent_id ON devices_group (parent_id);
"""


class Migration(migrations.Migration):
    dependencies = [("devices", "0010_split_groups_and_topology")]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                # Empty the device-parent column first: those groups become top level.
                migrations.RunSQL(
                    sql="UPDATE devices_group SET parent_device_id = NULL WHERE parent_device_id IS NOT NULL",
                    reverse_sql=migrations.RunSQL.noop),
                migrations.RunSQL(sql=REBUILD, reverse_sql=migrations.RunSQL.noop),
            ],
            state_operations=[
                migrations.RenameField(model_name="group", old_name="parent_group", new_name="parent"),
                migrations.RemoveConstraint(model_name="group", name="devices_group_single_parent"),
                migrations.RemoveField(model_name="group", name="parent_device"),
            ],
        ),
    ]
