using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SentinelSharkDotNet.Models;
using SentinelSharkDotNet.Core;

namespace SentinelSharkDotNet.Services;

public class ThreatQueueManager
{
    private readonly ConcurrentQueue<string> _queue = new();
    private readonly HashSet<string> _pendingIps = new();
    private readonly HashSet<string> _inProgressIps = new();
    private readonly object _lock = new();
    private bool _isRunning;
    private Task? _workerTask;
    private CancellationTokenSource? _cts;
    private double _backoffDelay = 1.0;
    private readonly double _maxBackoff = 60.0;
    private readonly ThreatIntelClient _client = new();

    public event Action<string, ThreatData>? ThreatResolved;
    public event Action<int, int>? QueueStatusChanged;

    public void EnqueueIp(string ip)
    {
        if (!_client.IsPublicIp(ip))
            return;

        var cached = ThreatCache.Instance.Get(ip);
        if (cached != null)
        {
            ThreatResolved?.Invoke(ip, cached);
            return;
        }

        lock (_lock)
        {
            if (_pendingIps.Contains(ip) || _inProgressIps.Contains(ip))
                return;
        }

        if (string.IsNullOrWhiteSpace(AppConfig.Instance.AbuseIpDbApiKey) && 
            string.IsNullOrWhiteSpace(AppConfig.Instance.VirusTotalApiKey) &&
            string.IsNullOrWhiteSpace(AppConfig.Instance.ShodanApiKey) &&
            string.IsNullOrWhiteSpace(AppConfig.Instance.IpInfoApiKey))
        {
            var defaultResult = new ThreatData
            {
                Domain = "No API Keys Set",
                NoKeys = true
            };
            ThreatResolved?.Invoke(ip, defaultResult);
            return;
        }

        lock (_lock)
        {
            _pendingIps.Add(ip);
        }
        
        _queue.Enqueue(ip);
        NotifyQueueStatus();
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();
        _workerTask = Task.Run(() => _WorkerLoop(_cts.Token));
    }

    public async Task Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        if (_cts != null)
        {
            _cts.Cancel();
            _cts.Dispose();
            _cts = null;
        }
        if (_workerTask != null)
        {
            try
            {
                await _workerTask;
            }
            catch (OperationCanceledException) { }
            _workerTask = null;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _pendingIps.Clear();
            _inProgressIps.Clear();
            _queue.Clear();
        }
        NotifyQueueStatus();
    }

    private void NotifyQueueStatus()
    {
        int pending, inProgress;
        lock (_lock)
        {
            pending = _pendingIps.Count;
            inProgress = _inProgressIps.Count;
        }
        QueueStatusChanged?.Invoke(pending, inProgress);
    }

    private async Task _WorkerLoop(CancellationToken token)
    {
        while (_isRunning && !token.IsCancellationRequested)
        {
            if (_queue.TryDequeue(out var ip))
            {
                lock (_lock)
                {
                    _pendingIps.Remove(ip);
                    _inProgressIps.Add(ip);
                }
                NotifyQueueStatus();
                int maxRpm = AppConfig.Instance.MaxRequestsPerMinute > 0 ? AppConfig.Instance.MaxRequestsPerMinute : 60;
                int delayMs = 60000 / maxRpm;
                
                try
                {
                    await Task.Delay(delayMs, token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                var cached = ThreatCache.Instance.Get(ip);
                if (cached != null)
                {
                    lock (_lock)
                    {
                        _inProgressIps.Remove(ip);
                    }
                    ThreatResolved?.Invoke(ip, cached);
                    NotifyQueueStatus();
                    continue;
                }

                var result = await _client.LookupIp(ip);

                if (result.Has429)
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(_backoffDelay), token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    
                    _backoffDelay = Math.Min(_backoffDelay * 2, _maxBackoff);
                    
                    lock (_lock)
                    {
                        _inProgressIps.Remove(ip);
                        _pendingIps.Add(ip);
                    }
                    _queue.Enqueue(ip);
                }
                else
                {
                    _backoffDelay = 1.0;
                    ThreatCache.Instance.Set(ip, result);
                    
                    lock (_lock)
                    {
                        _inProgressIps.Remove(ip);
                    }
                    ThreatResolved?.Invoke(ip, result);
                }
                NotifyQueueStatus();
            }
            else
            {
                try
                {
                    await Task.Delay(100, token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }
}
