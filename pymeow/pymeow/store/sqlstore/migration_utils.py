"""
**Setup Aerich for migrations:**

aerich init -t pymeow.store.sqlstore.config.TORTOISE_ORM
aerich init-db
"""

from ..sqlstore import Container


async def migrate_from_raw_sql(old_db_path: str, new_container: Container):
    """Migrate data from old raw SQL implementation to Tortoise ORM"""
    import sqlite3

    # Read from old database
    old_conn = sqlite3.connect(old_db_path)
    cursor = old_conn.cursor()

    # Migrate devices
    cursor.execute("SELECT * FROM whatsmeow_device")
    for _row in cursor.fetchall():
        # Convert and save to new format
        pass

    old_conn.close()
