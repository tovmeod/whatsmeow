from typing import Dict, Any
import os

def get_tortoise_config(db_url: str) -> Dict[str, Any]:
    """Generate Tortoise ORM configuration"""
    return {
        "connections": {"default": db_url},
        "apps": {
            "models": {
                "models": [
                    "pymeow.store.sqlstore.models.device",
                    "pymeow.store.sqlstore.models.session",
                    "pymeow.store.sqlstore.models.contacts",
                    "pymeow.store.sqlstore.models.appstate",
                    "pymeow.store.sqlstore.models.messages",
                ],
                "default_connection": "default",
            }
        },
    }

DATABASE_CONFIG = {
    "sqlite": "sqlite://./whatsapp_store.db",
    "postgresql": "postgres://user:pass@localhost:5432/whatsapp",
    "mysql": "mysql://user:pass@localhost:3306/whatsapp",
}
