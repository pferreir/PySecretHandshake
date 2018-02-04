import os
from asyncio import get_event_loop
from base64 import b64decode

import yaml
from nacl.signing import SigningKey

from secret_handshake import SHSServer

with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


async def _on_connect(conn):
    async for msg in conn:
        print(msg)


async def main():
    server_keypair = SigningKey(b64decode(config['private'][:-8])[:32])
    server = SHSServer('localhost', 8008, server_keypair)
    server.on_connect(_on_connect)
    await server.listen()

loop = get_event_loop()
loop.run_until_complete(main())
loop.run_forever()
loop.close()
