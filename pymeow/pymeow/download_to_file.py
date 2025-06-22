import typing
from pathlib import Path
from typing import Union

from .download import DownloadableMessage, download

if typing.TYPE_CHECKING:
    from .client import Client


async def download_to_file(
    client: "Client", msg: DownloadableMessage, file_path: Union[str, Path], decrypt: bool = True
) -> None:
    """Download media to a file.

    Args:
        client: The WhatsApp client instance
        msg: The downloadable message
        file_path: The path to save the file to
        decrypt: Whether to decrypt the media

    Raises:
        DownloadError: If download fails
    """
    data = await download(client, msg)
    # Write to file
    if isinstance(file_path, str):
        file_path = Path(file_path)
    if data is not None:
        file_path.write_bytes(data)
