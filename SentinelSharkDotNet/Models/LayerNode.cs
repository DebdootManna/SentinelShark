using System.Collections.Generic;

namespace SentinelSharkDotNet.Models;

public class LayerNode
{
    public string Label { get; set; } = "";
    public string Value { get; set; } = "";
    public string? ColorHint { get; set; }
    public bool IsBold { get; set; }
    public List<LayerNode> Children { get; set; } = new();
}
