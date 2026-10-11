import asyncio,json,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import local_server

class Reader:
 def __init__(self,data): self.chunks=[data[i:i+7] for i in range(0,len(data),7)]
 async def read(self,n): return self.chunks.pop(0) if self.chunks else b''
class Writer:
 def __init__(self): self.data=bytearray();self.closed=False;self.eof=False
 def write(self,b): self.data.extend(b)
 async def drain(self): pass
 def can_write_eof(self): return True
 def write_eof(self): self.eof=True
 def close(self): self.closed=True
 async def wait_closed(self): pass
 def get_extra_info(self,name): return ('192.168.200.1',12345)
class Server:
 async def serve_forever(self): await asyncio.Future()
 def close(self): pass
 async def wait_closed(self): pass
async def check():
 messages=json.load(open('midea-reboot-handshake.json'))
 device=bytes.fromhex(messages[0]['hex'])+bytes.fromhex(messages[2]['hex'])
 cloud=bytes.fromhex(messages[1]['hex'])
 handlers=[];client_writer=Writer();cloud_writer=Writer()
 async def start(handler,*a,**kw): handlers.append(handler);return Server()
 async def connect(host,port):
  assert (host,port)==('35.71.136.152',28443)
  return Reader(cloud),cloud_writer
 with tempfile.TemporaryDirectory() as logs:
  args=SimpleNamespace(logs=Path(logs),cert='certs/server.crt',key='certs/server.key',bind='192.168.200.164',proxy_port=28443,http_port=8080,https_port=8443,upstream='35.71.136.152',upstream_port=28443)
  with patch.object(asyncio,'start_server',start),patch.object(asyncio,'open_connection',connect):
   serving=asyncio.create_task(local_server.serve(args))
   while len(handlers)<3: await asyncio.sleep(0)
   await handlers[0](Reader(device),client_writer)
   serving.cancel()
   await asyncio.gather(serving,return_exceptions=True)
  assert bytes(cloud_writer.data)==device
  assert bytes(client_writer.data)==cloud
  assert client_writer.closed and cloud_writer.closed
  assert client_writer.eof and cloud_writer.eof
  entries=[json.loads(line) for line in (Path(logs)/'events.jsonl').read_text().splitlines()]
  assert sorted(e['type'] for e in entries if e['event']=='frame')==[1,2,8]
  assert not [e for e in entries if e['event']=='error']
  assert next(Path(logs).glob('*-device-to-cloud.bin')).read_bytes()==device
  assert next(Path(logs).glob('*-cloud-to-device.bin')).read_bytes()==cloud
 print('Bidirectional relay, unchanged bytes, raw logs, frame logs, EOF and cleanup verified with recorded packets and in-memory streams.')
asyncio.run(check())
