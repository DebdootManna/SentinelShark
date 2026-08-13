using System;
using System.Collections.Concurrent;
using SentinelSharkDotNet.Models;

namespace SentinelSharkDotNet.Core;

public class ThreatCache
{
    private readonly ConcurrentDictionary<string, (ThreatData Data, DateTime Expiry)> _cache = new();
    private readonly int _ttlHours;
    private readonly int _maxEntries;
    
    public static ThreatCache Instance { get; } = new();
    
    public ThreatCache(int ttlHours = 24, int maxEntries = 2000)
    {
        _ttlHours = ttlHours;
        _maxEntries = maxEntries;
    }
    
    public ThreatData? Get(string ip)
    {
        if (_cache.TryGetValue(ip, out var entry))
        {
            if (DateTime.UtcNow > entry.Expiry)
            {
                _cache.TryRemove(ip, out _);
                return null;
            }
            return entry.Data;
        }
        return null;
    }
    
    public void Set(string ip, ThreatData data)
    {
        if (_cache.Count >= _maxEntries)
        {
            Clear(); // Simplistic eviction
        }
        
        data.IsCached = true;
        _cache[ip] = (data, DateTime.UtcNow.AddHours(_ttlHours));
    }
    
    public void Clear()
    {
        _cache.Clear();
    }
}
