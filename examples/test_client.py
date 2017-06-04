import os
import yaml

from asyncio import get_event_loop
from base64 import b64decode

from nacl.signing import SigningKey

from secret_handshake import SHSClient


with open(os.path.expanduser('~/.ssb/secret')) as f:
    config = yaml.load(f)


async def main():
    async for msg in client:
        print(msg)


loop = get_event_loop()

server_pub_key = b64decode(config['public'][:-8])
client = SHSClient('localhost', 8008, SigningKey.generate(), server_pub_key, loop=loop)
client.connect()
loop.run_until_complete(main())

loop.close()
