using System;
using System.Collections.Generic;
using System.IO;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.Core;

public static class PcapWriter
{
    public static bool SavePacketsAuto(string filepath, List<PacketInfo> packets)
    {
        if (filepath.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                PcapNgWriter.SavePackets(filepath, packets);
                return true;
            }
            catch
            {
                return false;
            }
        }
        return SavePcapFile(filepath, packets);
    }

    public static bool SavePcapFile(string filepath, List<PacketInfo> packets)
    {
        try
        {
            using var fs = new FileStream(filepath, FileMode.Create);
            using var bw = new BinaryWriter(fs);
            
            // Write global header (24 bytes)
            bw.Write(0xa1b2c3d4u); // magic
            bw.Write((ushort)2);    // version major
            bw.Write((ushort)4);    // version minor  
            bw.Write(0);            // thiszone
            bw.Write(0u);           // sigfigs
            bw.Write(65535u);       // snaplen
            bw.Write(1u);           // network (Ethernet)
            
            foreach (var pkt in packets)
            {
                byte[] data = pkt.RawBytes ?? BuildEthernetFrame(pkt);
                
                uint tsSec = 0;
                uint tsUsec = 0;
                
                if (DateTime.TryParse(pkt.Time, out DateTime ts))
                {
                    tsSec = (uint)((DateTimeOffset)ts).ToUnixTimeSeconds();
                    tsUsec = (uint)(ts.Millisecond * 1000 + ts.Microsecond);
                }
                else
                {
                    tsSec = (uint)((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();
                }

                uint length = (uint)data.Length;

                // Write per-packet header (16 bytes)
                bw.Write(tsSec);        // ts_sec
                bw.Write(tsUsec);       // ts_usec
                bw.Write(length);       // incl_len
                bw.Write(length);       // orig_len
                
                // Write packet data
                bw.Write(data);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }
    
    private static byte[] BuildEthernetFrame(PacketInfo pkt)
    {
        // 14-byte Ethernet header fallback
        // dst MAC: 00:11:22:33:44:55, src MAC: 66:77:88:99:aa:bb, EtherType: 0x0800 (IPv4)
        byte[] frame = new byte[14 + 20]; // 14 eth + 20 ipv4
        
        // Dst Mac
        frame[0] = 0x00; frame[1] = 0x11; frame[2] = 0x22; frame[3] = 0x33; frame[4] = 0x44; frame[5] = 0x55;
        // Src Mac
        frame[6] = 0x66; frame[7] = 0x77; frame[8] = 0x88; frame[9] = 0x99; frame[10] = 0xaa; frame[11] = 0xbb;
        // EtherType IPv4
        frame[12] = 0x08; frame[13] = 0x00;

        // Dummy payload
        for (int i = 14; i < frame.Length; i++)
        {
            frame[i] = 0x00;
        }
        
        return frame;
    }
}
