"""Export authorized links only. Private input map is never copied to output."""
import argparse,csv,hashlib,json,re,subprocess,sys
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'live'))
from engine import decode_line,tshark_command,FIELDS
from feedback import report_kind
META=['t_rel_s','client','ap','direction','format','Nr','Nc','Ng','bandwidth_mhz','feedback','codebook','bits_psi','subcarriers','series_id']
def sha256(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def export_capture(path,output,client,ap,code):
 if not re.fullmatch('C0[1-5]',code):raise ValueError('Expected C01–C05')
 from dependencies import require_fields
 require_fields(FIELDS)
 path=Path(path);before=path.stat();rows=[];origin=None;last=None;rejected=0;reports=0
 cmd=tshark_command(path,client,ap)
 # Decode only the chosen pair; a first-packet record preserves the true origin.
 cmd+=['-Y',f'frame.number==1 || (wlan.ta=={client} && wlan.ra=={ap}) || (wlan.ta=={ap} && wlan.ra=={client})']
 import tempfile
 with tempfile.TemporaryFile(mode='w+') as err:
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=err,text=True)
  for line in proc.stdout:
   parts=line.rstrip('\r\n').split('|')
   if len(parts)!=len(FIELDS):raise ValueError('Invalid tshark field count')
   ts=float(parts[0]);origin=ts if origin is None else origin;last=ts
   paired=(parts[1].lower(),parts[12].lower()) in ((client,ap),(ap,client))
   if paired and report_kind(dict(zip(FIELDS,parts))):reports+=1
   try:r=decode_line(line,client,ap)
   except (ValueError,KeyError,IndexError):
    if paired:rejected+=1
    continue
   if 'psi' not in r:continue
   if not np.isfinite(r['psi']).all():raise ValueError('Nonfinite angle')
   f=r['feedback'];row=[f'{ts-origin:.9f}',code,'AP01',f['direction'],f['kind'],f['nr'],f['nc'],f['grouping'],f['width'],f['feedback'],f['codebook'],f['bits_psi'],f['subcarriers'],r['series_id']]
   rows.append(row+[format(float(x),'.9g') for x in r['psi']])
  proc.stdout.close()
  if proc.wait():raise RuntimeError('tshark failed; export aborted')
 after=path.stat()
 if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Source changed during export')
 width=max((len(r)-len(META) for r in rows),default=0)
 output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
 with output.open('w',newline='',encoding='utf-8') as f:
  w=csv.writer(f,lineterminator='\n');w.writerow(META+[f'psi_{k:04d}_rad' for k in range(width)])
  for row in rows:w.writerow(row+['']*(len(META)+width-len(row)))
 return dict(rows=len(rows),reports=reports,rejected=rejected,pcap_sha256=sha256(path),derived_sha256=sha256(output),observed_span_s=round((last-origin) if origin is not None else 0,6))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--private-map',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 specs=json.loads(a.private_map.read_text());catalog=[];manifest=[]
 for s in specs:
  cid=s['capture_id']
  if not re.fullmatch(r'CAP\d{4}',cid):raise ValueError('Invalid capture alias')
  relative=f'captures/{cid}.csv';r=export_capture(s['source'],a.out/relative,s['client_mac'],s['ap_mac'],s['client'])
  catalog.append(dict(capture_id=cid,client=s['client'],ap='AP01',protocol=s['protocol'],condition=s['condition'],preparation_s=s['preparation_s'],planned_duration_s=s['duration_s'],decoded_rows=r['rows'],observed_reports=r['reports'],rejected_reports=r['rejected']))
  manifest.append(dict(capture_id=cid,pcap_sha256=r['pcap_sha256'],derived_file=relative,derived_sha256=r['derived_sha256']))
  print(cid,r['rows'],r['rejected'],flush=True)
 for name,items in [('catalog.csv',catalog),('MANIFEST.csv',manifest)]:
  with (a.out/name).open('w',newline='',encoding='utf-8') as f:
   w=csv.DictWriter(f,fieldnames=list(items[0]),lineterminator='\n');w.writeheader();w.writerows(items)
if __name__=='__main__':main()
