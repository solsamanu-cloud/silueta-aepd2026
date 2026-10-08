"""Generate packets from scratch. No radio and no captured bytes are used."""
import argparse,math,struct
from pathlib import Path
CLIENT='02:00:00:00:00:01';AP='02:00:00:00:00:06'
def mac(s):return bytes.fromhex(s.replace(':',''))
def packet(i,psi,client=CLIENT,ap=AP):
 # Radiotap: rate 24 Mb/s, frequency 5180 MHz, signal -50 dBm.
 rt=struct.pack('<BBHI',0,0,15,0x2c)+bytes([48,0])+struct.pack('<HHb',5180,0x140,-50)
 header=struct.pack('<HH',0xe0,0)+mac(ap)+mac(client)+mac(ap)+struct.pack('<H',(i%4096)<<4)
 control=(1<<3)|(1<<10)|(1<<15) # 2x1, 20 MHz, Ng1, 6/4 bits, complete first segment
 word=3+(int(psi)<<6);bits=sum(word<<(10*k) for k in range(52))
 body=bytes([20])+bits.to_bytes(65,'little')
 return rt+header+bytes([21,0])+control.to_bytes(3,'little')+body
def generate(path,duration=60,hz=5):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('wb') as f:
  f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127))
  for i in range(int(duration*hz)):
   t=1000+i/hz;psi=round(7+5*math.sin(2*math.pi*.23*i/hz));b=packet(i,psi)
   f.write(struct.pack('<IIII',int(t),round(t%1*1e6),len(b),len(b)));f.write(b)
 return path
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('output');p.add_argument('--duration',type=int,default=60);a=p.parse_args();generate(a.output,a.duration)
