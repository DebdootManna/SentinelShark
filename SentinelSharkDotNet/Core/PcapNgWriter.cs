using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.Core;

public class PcapNgWriter
{
    public static void SavePackets(string filePath, IEnumerable<PacketInfo> packets)
    {
        using var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        using var writer = new BinaryWriter(stream);

        // 1. Section Header Block (SHB) - 28 bytes
        writer.Write((uint)0x0A0D0D0A); // Block Type
        writer.Write((uint)28);         // Block Total Length
        writer.Write((uint)0x1A2B3C4D); // Byte-Order Magic
        writer.Write((ushort)1);        // Major Version
        writer.Write((ushort)0);        // Minor Version
        writer.Write((long)-1);         // Section Length (unspecified)
        writer.Write((uint)28);         // Block Total Length

        // 2. Interface Description Block (IDB) - 20 bytes
        writer.Write((uint)0x00000001); // Block Type (IDB)
        writer.Write((uint)20);         // Block Total Length
        writer.Write((ushort)1);        // LinkType (1 = Ethernet)
        writer.Write((ushort)0);        // Reserved
        writer.Write((uint)65535);      // SnapLen
        writer.Write((uint)20);         // Block Total Length

        // 3. Enhanced Packet Blocks (EPB)
        long epochMicrosecondsStart = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
        long counter = 0;

        foreach (var pkt in packets)
        {
            byte[] raw = pkt.RawBytes ?? Array.Empty<byte>();
            if (raw.Length == 0)
            {
                // Dummy Ethernet header + IP packet if no raw bytes
                raw = Encoding.UTF8.GetBytes(pkt.Info ?? "");
            }

            uint capLen = (uint)raw.Length;
            uint origLen = (uint)raw.Length;

            int padding = (4 - (raw.Length % 4)) % 4;
            uint blockLen = 32 + (uint)raw.Length + (uint)padding;

            long tsMicroseconds = epochMicrosecondsStart + (counter++ * 1000);
            uint tsHigh = (uint)(tsMicroseconds >> 32);
            uint tsLow = (uint)(tsMicroseconds & 0xFFFFFFFF);

            writer.Write((uint)0x00000006); // Block Type (EPB)
            writer.Write((uint)blockLen);   // Block Total Length
            writer.Write((uint)0);          // Interface ID
            writer.Write(tsHigh);           // Timestamp High
            writer.Write(tsLow);            // Timestamp Low
            writer.Write(capLen);           // Captured Len
            writer.Write(origLen);          // Original Len
            writer.Write(raw);              // Packet Payload

            for (int i = 0; i < padding; i++)
            {
                writer.Write((byte)0);      // 32-bit Alignment Padding
            }

            writer.Write(blockLen);         // Block Total Length
        }
    }
}
