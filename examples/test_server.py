import os
import yaml

from asyncio import get_event_loop
from base64 import b64decode

from nacl.signing import SigningKey

from secret_handshake import SHSServer


with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


async def main():
    async for msg in server:
        print(msg)


loop = get_event_loop()

server_keypair = SigningKey(b64decode(config['private'][:-8])[:32])
server = SHSServer('localhost', 8008, server_keypair, loop=loop)
server.on_connect(main)
server.listen()

loop.run_forever()
loop.close()
