"""
Update handling for WhatsApp.

Port of whatsmeow/update.go
"""

import re
from typing import Optional

import aiohttp

from .socket import constants
from .store.clientpayload import WAVersionContainer

# Regex to extract client revision from web.whatsapp.com
client_version_regex = re.compile(r'"client_revision":(\d+),')


async def get_latest_version(http_client: Optional[aiohttp.ClientSession] = None) -> Optional[WAVersionContainer]:
    """
    Returns the latest version number from web.whatsapp.com.

    After fetching, you can update the version to use with store.set_wa_version, e.g.

    ```python
    latest_ver = await get_latest_version()
    if latest_ver:
        store.set_wa_version(latest_ver)
    ```

    Args:
        http_client: Optional aiohttp client session to use for the request

    Returns:
        WAVersionContainer with the version information or None if an error occurred

    Raises:
        Exception: If there's an error fetching or parsing the version
    """
    should_close_client = False
    if http_client is None:
        http_client = aiohttp.ClientSession()
        should_close_client = True

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with http_client.get(constants.ORIGIN, headers=headers) as resp:
            if resp.status != 200:
                raise Exception(f"Unexpected response with status {resp.status}: {await resp.text()}")

            data = await resp.text()
            match = client_version_regex.search(data)

            if not match:
                raise Exception("Version number not found")

            parsed_ver = int(match.group(1))
            return WAVersionContainer(2, 3000, parsed_ver)

    except Exception as e:
        raise Exception(f"Failed to get latest version: {e}")

    finally:
        if should_close_client:
            await http_client.close()
