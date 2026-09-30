using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using DnsLoadBalancer.Models;

namespace DnsLoadBalancer.Services;

/// <summary>
/// Health and latency data for a single server IP.
/// </summary>
public sealed class ServerIpInfo
{
    public required IPAddress Address { get; init; }
    public required string IpString { get; init; }
    public int OriginalIndex { get; init; }
    public bool IsHealthy { get; set; }
    public long LatencyMs { get; set; } = long.MaxValue;
    public int ConsecutiveFailures { get; set; }
    public DateTime LastCheckUtc { get; set; }
}

/// <summary>
/// Thread-safe IP pool for a single domain.
/// Manages health status, latency ranking, and shuffled selection.
/// </summary>
public sealed class DomainPool
{
    private readonly object _lock = new();
    private readonly List<ServerIpInfo> _allIps = [];
    private volatile IReadOnlyList<ServerIpInfo> _healthyIps = [];

    public string Domain { get; }
    public string IpFilePath { get; }
    public int HealthyCount => _healthyIps.Count;
    public int TotalCount { get { lock (_lock) return _allIps.Count; } }

    public DomainPool(string domain, string ipFilePath)
    {
        Domain = domain;
        IpFilePath = ipFilePath;
    }

    /// <summary>
    /// Loads IPs from a text file (one IP per line). Thread-safe.
    /// </summary>
    public void LoadFromFile(ILogger logger)
    {
        try
        {
            string fullPath = Path.GetFullPath(IpFilePath);
            if (!File.Exists(fullPath))
            {
                logger.LogWarning("[{Domain}] IP file not found: {Path} — skipping", Domain, fullPath);
                return;
            }

            var expandedIps = new List<string>();
            foreach (var line in File.ReadAllLines(fullPath))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;
                expandedIps.AddRange(ExpandIpRange(trimmed));
            }

            var uniqueIps = expandedIps.Distinct().ToList();

            lock (_lock)
            {
                _allIps.Clear();
                int index = 0;
                foreach (var line in uniqueIps)
                {
                    _allIps.Add(new ServerIpInfo
                    {
                        Address = IPAddress.Parse(line),
                        IpString = line,
                        OriginalIndex = index++
                    });
                }
            }

            logger.LogInformation("[{Domain}] Loaded {Count} IPs from {Path}", Domain, uniqueIps.Count, fullPath);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[{Domain}] Failed to load IPs from {Path}", Domain, IpFilePath);
        }
    }

    private static IEnumerable<string> ExpandIpRange(string line)
    {
        if (!line.Contains('/'))
        {
            if (IPAddress.TryParse(line, out _))
                yield return line;
            yield break;
        }

        var parts = line.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32)
            yield break;

        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            yield break; // Only IPv4 for CIDR expansion for now

        byte[] ipBytes = ip.GetAddressBytes();
        uint ipUint = (uint)((ipBytes[0] << 24) | (ipBytes[1] << 16) | (ipBytes[2] << 8) | ipBytes[3]);
        uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
        uint startIp = ipUint & mask;
        uint endIp = startIp | ~mask;

        ulong count = (ulong)endIp - startIp + 1;
        
        // Prevent huge allocations from typos (e.g. /8 or /0)
        if (count > 65536) 
            yield break;

        for (ulong i = 0; i < count; i++)
        {
            uint currentIp = (uint)(startIp + i);
            byte[] bytes = new byte[4];
            bytes[0] = (byte)(currentIp >> 24);
            bytes[1] = (byte)(currentIp >> 16);
            bytes[2] = (byte)(currentIp >> 8);
            bytes[3] = (byte)(currentIp);
            yield return new IPAddress(bytes).ToString();
        }
    }

    /// <summary>Returns a snapshot of all tracked IPs.</summary>
    public IReadOnlyList<ServerIpInfo> GetAllIps()
    {
        try
        {
            lock (_lock) return _allIps.ToList();
        }
        catch
        {
            return [];
        }
    }

    /// <summary>Updates health status and latency for a specific IP.</summary>
    public void UpdateHealth(string ip, bool healthy, long latencyMs)
    {
        try
        {
            lock (_lock)
            {
                var info = _allIps.Find(x => x.IpString == ip);
                if (info is null) return;

                info.IsHealthy = healthy;
                info.LastCheckUtc = DateTime.UtcNow;

                if (healthy)
                {
                    info.LatencyMs = latencyMs;
                    info.ConsecutiveFailures = 0;
                }
                else
                {
                    info.ConsecutiveFailures++;
                    info.LatencyMs = long.MaxValue;
                }
            }
        }
        catch { /* Silently ignore update failures */ }
    }

    /// <summary>Rebuilds the healthy IP list based on the selected routing mode.</summary>
    public void RefreshHealthyList(ILogger logger, string routingMode)
    {
        try
        {
            List<ServerIpInfo> snapshot;
            lock (_lock)
            {
                var query = _allIps.Where(x => x.IsHealthy);

                if (routingMode.Equals("Sequential", StringComparison.OrdinalIgnoreCase))
                {
                    snapshot = query.OrderBy(x => x.OriginalIndex).ToList();
                }
                else // LowestPing
                {
                    snapshot = query.OrderBy(x => x.LatencyMs).ToList();
                }
            }

            _healthyIps = snapshot;
            logger.LogInformation("[{Domain}] Healthy pool: {Count}/{Total} IPs",
                Domain, snapshot.Count, TotalCount);

            if (snapshot.Count > 0)
            {
                var topIps = snapshot.Take(3).Select(x => x.IpString).ToList();
                logger.LogInformation("[{Domain}] Top IPs in queue: {Ips}", Domain, string.Join(", ", topIps));
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[{Domain}] Failed to refresh healthy list", Domain);
        }
    }

    /// <summary>Returns the best N healthy IPs based on strategy.</summary>
    public List<IPAddress> GetBestIps(int count, string routingMode)
    {
        try
        {
            var healthy = _healthyIps;
            if (healthy.Count == 0) return [];

            var selected = healthy.Take(Math.Min(count, healthy.Count)).ToList();

            // If LowestPing, shuffle the selected fastest IPs for round-robin
            // If Sequential, return them exactly in original file order
            if (routingMode.Equals("LowestPing", StringComparison.OrdinalIgnoreCase))
            {
                for (int i = selected.Count - 1; i > 0; i--)
                {
                    int j = Random.Shared.Next(i + 1);
                    (selected[i], selected[j]) = (selected[j], selected[i]);
                }
            }

            return selected.Select(x => x.Address).ToList();
        }
        catch
        {
            return [];
        }
    }
}

/// <summary>
/// Manages multiple domain pools. Thread-safe.
/// Each domain has its own IP pool with independent health tracking.
/// </summary>
public sealed class IpPoolManager
{
    private readonly ConcurrentDictionary<string, DomainPool> _pools = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOptionsMonitor<DnsLoadBalancerOptions> _options;
    private readonly ILogger<IpPoolManager> _logger;

    public IpPoolManager(IOptionsMonitor<DnsLoadBalancerOptions> options, ILogger<IpPoolManager> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <summary>Registers a new domain pool and loads its IP list.</summary>
    public DomainPool AddDomain(string domain, string ipFilePath)
    {
        try
        {
            var pool = new DomainPool(domain, ipFilePath);
            pool.LoadFromFile(_logger);
            _pools[domain] = pool;
            _logger.LogInformation("Domain pool registered: {Domain} ({Count} IPs)", domain, pool.TotalCount);
            return pool;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add domain pool: {Domain}", domain);
            var emptyPool = new DomainPool(domain, ipFilePath);
            _pools[domain] = emptyPool;
            return emptyPool;
        }
    }

    /// <summary>
    /// Finds the pool matching a DNS query name.
    /// Supports exact match and subdomain match.
    /// </summary>
    public DomainPool? FindPool(string queryName)
    {
        try
        {
            if (_pools.TryGetValue(queryName, out var pool))
                return pool;

            foreach (var (domain, p) in _pools)
            {
                if (queryName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                    return p;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error finding pool for query: {Name}", queryName);
        }

        return null;
    }

    /// <summary>Returns all registered domain pools.</summary>
    public IEnumerable<DomainPool> GetAllPools()
    {
        try { return _pools.Values.ToList(); }
        catch { return []; }
    }

    /// <summary>Reloads the IP list for a specific domain.</summary>
    public void ReloadPool(string domain)
    {
        try
        {
            if (_pools.TryGetValue(domain, out var pool))
                pool.LoadFromFile(_logger);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reload pool: {Domain}", domain);
        }
    }
}
