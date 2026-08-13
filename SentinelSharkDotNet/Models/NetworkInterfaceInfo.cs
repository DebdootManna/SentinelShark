namespace SentinelSharkDotNet.Models;

public class NetworkInterfaceInfo
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string IPv4Address { get; set; } = "N/A";
    public string TSharkId { get; set; } = "";
    public bool IsActive { get; set; }
    public long BytesReceived { get; set; }
    public long BytesSent { get; set; }
}
