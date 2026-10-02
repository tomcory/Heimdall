#!/usr/bin/env python3
"""
Reads a packet capture taken on the VPN's TUN interface and reports how Heimdall's TCP side
behaved towards the device: how long it took to acknowledge data, how often the device had to
retransmit, and whether its FIN and RST segments carry the ACK flag.

Capture on a rooted emulator while traffic runs, then analyse:

  adb shell su -c "tcpdump -i tun0 -n -s 96 -w /data/local/tmp/cap.pcap tcp port 443"
  adb pull /data/local/tmp/cap.pcap
  scripts/stress/tcp-capture-stats.py cap.pcap 443 [device-address, default 10.120.0.1]
"""
import struct, sys, collections
def packets(path):
    f=open(path,'rb'); gh=f.read(24)
    magic=struct.unpack('<I',gh[:4])[0]
    nano = magic==0xa1b23c4d
    link=struct.unpack('<I',gh[20:24])[0]
    while True:
        h=f.read(16)
        if len(h)<16: break
        ts,frac,incl,orig=struct.unpack('<IIII',h)
        d=f.read(incl)
        t=ts+frac/(1e9 if nano else 1e6)
        if link==113: d=d[16:]      # Linux cooked
        elif link==1: d=d[14:]
        if not d or d[0]>>4!=4: continue
        ihl=(d[0]&15)*4; tot=struct.unpack('>H',d[2:4])[0]
        if d[9]!=6: continue
        src=d[12:16]; dst=d[16:20]
        tcp=d[ihl:]
        sp,dp,seq,ack=struct.unpack('>HHII',tcp[:12]); off=(tcp[12]>>4)*4; flags=tcp[13]
        ln=tot-ihl-off
        yield t,src,sp,dst,dp,seq,ack,flags,ln
dev=bytes(int(x) for x in (sys.argv[3] if len(sys.argv) > 3 else "10.120.0.1").split("."))
port=int(sys.argv[2])
pending=collections.defaultdict(list)  # flow -> [(t, endseq)]
seen=collections.defaultdict(set)
delays=[]; retrans=0; data=0; finNoAck=0; rst=0; rstNoAck=0
for t,src,sp,dst,dp,seq,ack,flags,ln in packets(sys.argv[1]):
    if src==dev and dp==port:
        key=(sp,dst)
        if ln>0:
            data+=1
            if (seq,ln) in seen[key]: retrans+=1
            else:
                seen[key].add((seq,ln)); pending[key].append((t,(seq+ln)&0xffffffff))
    elif dst==dev and sp==port:
        key=(dp,src)
        if flags&0x01 and not flags&0x10: finNoAck+=1
        if flags&0x04:
            rst+=1
            if not flags&0x10: rstNoAck+=1
        if flags&0x10:
            rest=[]
            for (t0,end) in pending[key]:
                if ((ack-end)&0xffffffff) < 0x80000000: delays.append(t-t0)
                else: rest.append((t0,end))
            pending[key]=rest
delays.sort()
def pct(p): return delays[min(len(delays)-1,int(len(delays)*p))]*1000 if delays else float('nan')
print(f"device data segments: {data}, retransmitted by the device: {retrans}")
print(f"time until the VPN acknowledged a data segment (ms): median {pct(.5):.1f}, p90 {pct(.9):.1f}, p99 {pct(.99):.1f}, max {pct(1):.1f}; over 200 ms: {sum(1 for d in delays if d>0.2)} of {len(delays)}")
print(f"never acknowledged: {sum(len(v) for v in pending.values())}")
print(f"FINs from the VPN without ACK flag: {finNoAck}; RSTs from the VPN: {rst} (without ACK flag: {rstNoAck})")
