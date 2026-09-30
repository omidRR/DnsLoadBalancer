using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DnsLoadBalancer.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DnsLoadBalancer.Services;

public sealed class TlsHealthCheckService : BackgroundService
{
    private readonly IpPoolManager _ipPool;
    private readonly DnsLoadBalancerOptions _options;
    private readonly ILogger<TlsHealthCheckService> _logger;
    private readonly List<FileSystemWatcher> _watchers = [];
    private string? _serverPublicIp;

    public TlsHealthCheckService(
        IpPoolManager ipPool,
        IOptions<DnsLoadBalancerOptions> options,
        ILogger<TlsHealthCheckService> logger)
    {
        _ipPool = ipPool;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            try
            {
                using var http = new HttpClient();
                _serverPublicIp = (await http.GetStringAsync("https://api.ipify.org")).Trim();
                _logger.LogInformation("Server Public IP detected as: {Ip}", _serverPublicIp);
            }
            catch
            {
                _logger.LogWarning("Could not detect server public IP for domain verification.");
            }

            foreach (var dc in _options.Domains)
            {
                try
                {
                    _ipPool.AddDomain(dc.Name, dc.IpListFilePath);
                    SetupFileWatcher(dc.Name, Path.GetFullPath(dc.IpListFilePath));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to initialize domain: {Domain}", dc.Name);
                }
            }

            var sniMode = string.IsNullOrEmpty(_options.TlsCheckDomain)
                ? "per-domain (own SNI)"
                : _options.TlsCheckDomain;
            _logger.LogInformation(
                "TLS Health Checker started | SNI: {SniMode} | Interval: {Sec}s | Timeout: {Ms}ms | Domains: {Count}",
                sniMode, _options.TlsCheckIntervalSeconds, _options.TlsTimeoutMs, _options.Domains.Count);

            while (!stoppingToken.IsCancellationRequested)
            {
                await RunHealthCheckCycleAsync(stoppingToken);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(_options.TlsCheckIntervalSeconds), stoppingToken);
                }
                catch (OperationCanceledException) { break; }
            }
        }
        catch (OperationCanceledException) { /* Normal shutdown */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fatal error in TLS Health Checker");
        }
        finally
        {
            foreach (var w in _watchers)
            {
                try { w.Dispose(); } catch { }
            }
            _logger.LogInformation("TLS Health Checker stopped.");
        }
    }

    private async Task RunHealthCheckCycleAsync(CancellationToken ct)
    {
        try
        {
            var allPools = _ipPool.GetAllPools().ToList();
            int totalIps = allPools.Sum(p => p.GetAllIps().Count);
            if (totalIps == 0)
            {
                _logger.LogWarning("No IPs loaded across all domains — skipping health check.");
                return;
            }

            _logger.LogInformation("--- Health check cycle starting | {Domains} domains | {Total} IPs ---",
                allPools.Count, totalIps);

            var sw = Stopwatch.StartNew();
            using var semaphore = new SemaphoreSlim(_options.MaxConcurrentChecks);
            var allTasks = new List<Task>();

            foreach (var pool in allPools)
            {
                allTasks.Add(Task.Run(async () =>
                {
                    int healthyCount = 0;
                    int targetCount = _options.MaxHealthyIpsTarget;
                    var poolTasks = new List<Task>();

                    foreach (var ipInfo in pool.GetAllIps())
                    {
                        if (targetCount > 0 && Volatile.Read(ref healthyCount) >= targetCount)
                        {
                            pool.UpdateHealth(ipInfo.IpString, false, long.MaxValue);
                            continue;
                        }

                        await semaphore.WaitAsync(ct);

                        if (targetCount > 0 && Volatile.Read(ref healthyCount) >= targetCount)
                        {
                            semaphore.Release();
                            pool.UpdateHealth(ipInfo.IpString, false, long.MaxValue);
                            continue;
                        }

                        poolTasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                var checkDomain = string.IsNullOrEmpty(_options.TlsCheckDomain)
                                    ? pool.Domain
                                    : _options.TlsCheckDomain;
                                var (healthy, latencyMs) = await PerformTlsHandshakeAsync(
                                    ipInfo.IpString, checkDomain, _options.TlsPort,
                                    _options.TlsTimeoutMs, _options.ValidateTlsCertificate, ct,
                                    _options.UploadTestSizeKB);

                                pool.UpdateHealth(ipInfo.IpString, healthy, latencyMs);

                                if (healthy)
                                {
                                    Interlocked.Increment(ref healthyCount);
                                    _logger.LogInformation("  OK    [{Domain}] {Ip} ({Ms}ms)", pool.Domain, ipInfo.IpString, latencyMs);
                                }
                                else
                                {
                                    _logger.LogWarning("  FAIL  [{Domain}] {Ip}", pool.Domain, ipInfo.IpString);
                                }
                            }
                            catch (OperationCanceledException) { /* Shutdown */ }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "  ERROR [{Domain}] {Ip}", pool.Domain, ipInfo.IpString);
                                pool.UpdateHealth(ipInfo.IpString, false, -1);
                            }
                            finally
                            {
                                semaphore.Release();
                            }
                        }, ct));
                    }
                    await Task.WhenAll(poolTasks);
                }, ct));
            }

            try { await Task.WhenAll(allTasks); }
            catch (OperationCanceledException) { return; }
            catch { /* Individual task errors already logged */ }

            // Refresh healthy lists for all pools
            foreach (var pool in allPools)
            {
                pool.RefreshHealthyList(_logger, _options.RoutingMode);

                // --- Verify Domain DNS Status ---
                try
                {
                    var hostEntry = await System.Net.Dns.GetHostEntryAsync(pool.Domain, ct);
                    var resolvedIps = hostEntry.AddressList.Select(a => a.ToString()).ToList();

                    var poolIps = pool.GetAllIps().Select(x => x.IpString).ToHashSet();
                    bool isDelegatedToUs = resolvedIps.Any(ip => poolIps.Contains(ip));
                    bool isServerIp = _serverPublicIp != null && resolvedIps.Contains(_serverPublicIp);
                    bool isCloudflareProxy = resolvedIps.Any(ip => ip.StartsWith("104.") || ip.StartsWith("172.6"));

                    if (isDelegatedToUs)
                        _logger.LogInformation("  ✅  [{Domain}] Global DNS is correctly routing to our Load Balancer IPs.", pool.Domain);
                    else if (isCloudflareProxy)
                        _logger.LogWarning("  ⚠️  [{Domain}] PROXY IS ON (Cloudflare CDN). Custom DNS will NOT work!", pool.Domain);
                    else if (isServerIp)
                        _logger.LogWarning("  ⚠️  [{Domain}] Domain has an A record pointing to this Ubuntu server instead of NS delegation!", pool.Domain);
                    else
                        _logger.LogWarning("  ❌  [{Domain}] Domain is NOT delegated to this server yet. (Resolves to: {Ips})", pool.Domain, string.Join(", ", resolvedIps));
                }
                catch
                {
                    _logger.LogWarning("  ❌  [{Domain}] Could not resolve domain in public DNS (Not configured yet).", pool.Domain);
                }

                var healthyCount = pool.HealthyCount;
                var allCount = pool.GetAllIps().Count;
                _logger.LogInformation("[{Domain}] Healthy pool: {Healthy}/{Total} IPs", pool.Domain, healthyCount, allCount);

                var topIps = pool.GetBestIps(3, _options.RoutingMode);
                if (topIps.Count > 0)
                    _logger.LogInformation("[{Domain}] Top IPs in queue: {Ips}", pool.Domain, string.Join(", ", topIps));
            }

            sw.Stop();
            int totalHealthy = allPools.Sum(p => p.HealthyCount);
            _logger.LogInformation("--- Health check completed in {Ms}ms | {Healthy}/{Total} healthy ---",
                sw.ElapsedMilliseconds, totalHealthy, totalIps);
        }
        catch (OperationCanceledException) { /* Normal shutdown */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during health check cycle");
        }
    }

    private static async Task<(bool Healthy, long LatencyMs)> PerformTlsHandshakeAsync(
        string ip, string checkDomain, int port, int timeoutMs, bool validateCert, CancellationToken ct,
        int uploadSizeKB = 0)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);

            using var tcpClient = new TcpClient();
            tcpClient.SendBufferSize = 65536;
            var sw = Stopwatch.StartNew();

            await tcpClient.ConnectAsync(ip, port, cts.Token);

            using var sslStream = validateCert
                ? new SslStream(tcpClient.GetStream())
                : new SslStream(tcpClient.GetStream(), false, (_, _, _, _) => true);

            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = checkDomain,
                EnabledSslProtocols = SslProtocols.None
            }, cts.Token);

            if (uploadSizeKB > 0)
            {
                int totalBytes = uploadSizeKB * 1024;
                var bodyData = new byte[totalBytes];
                Random.Shared.NextBytes(bodyData);

                var header = $"POST /cdn-cgi/trace HTTP/1.1\r\nHost: {checkDomain}\r\nContent-Type: application/octet-stream\r\nContent-Length: {totalBytes}\r\nConnection: close\r\n\r\n";
                var headerBytes = Encoding.ASCII.GetBytes(header);
                await sslStream.WriteAsync(headerBytes, cts.Token);

                var uploadSw = Stopwatch.StartNew();
                int chunkSize = 16384;
                int sent = 0;
                while (sent < totalBytes)
                {
                    int remaining = Math.Min(chunkSize, totalBytes - sent);
                    await sslStream.WriteAsync(bodyData.AsMemory(sent, remaining), cts.Token);
                    sent += remaining;
                }
                await sslStream.FlushAsync(cts.Token);

                var buffer = new byte[1024];
                int bytesRead = await sslStream.ReadAsync(buffer, cts.Token);
                uploadSw.Stop();
                sw.Stop();

                if (bytesRead == 0) return (false, -1);

                var response = Encoding.ASCII.GetString(buffer, 0, Math.Min(bytesRead, 64));
                if (response.StartsWith("HTTP/"))
                {
                    var parts = response.Split(' ');
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int statusCode) && statusCode >= 500)
                        return (false, -1);
                    return (true, uploadSw.ElapsedMilliseconds);
                }
                return (false, -1);
            }
            else
            {
                sw.Stop();
                return (true, sw.ElapsedMilliseconds);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (false, -1);
        }
        catch
        {
            return (false, -1);
        }
    }

    private void SetupFileWatcher(string domain, string fullPath)
    {
        try
        {
            var directory = Path.GetDirectoryName(fullPath);
            var fileName = Path.GetFileName(fullPath);
            if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory)) return;

            var watcher = new FileSystemWatcher(directory, fileName)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            watcher.Changed += (_, _) =>
            {
                try
                {
                    Thread.Sleep(500);
                    _ipPool.ReloadPool(domain);
                    _logger.LogInformation("[{Domain}] IP list file changed — reloaded.", domain);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[{Domain}] Failed to reload IP list after file change.", domain);
                }
            };
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to setup file watcher for {Domain}", domain);
        }
    }
}
