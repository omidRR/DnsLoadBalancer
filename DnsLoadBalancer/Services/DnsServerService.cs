using System.Net;
using System.Net.Sockets;
using DnsLoadBalancer.Dns;
using DnsLoadBalancer.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DnsLoadBalancer.Services;

/// <summary>
/// Background service running a DNS server on UDP and TCP simultaneously.
/// Matches incoming queries against registered domain pools and responds
/// with healthy IPs. All methods are wrapped in try-catch.
/// </summary>
public sealed class DnsServerService : BackgroundService
{
    private readonly IpPoolManager _ipPool;
    private readonly DnsLoadBalancerOptions _options;
    private readonly ILogger<DnsServerService> _logger;
    private long _requestCount;

    public DnsServerService(
        IpPoolManager ipPool,
        IOptions<DnsLoadBalancerOptions> options,
        ILogger<DnsServerService> logger)
    {
        _ipPool = ipPool;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            _logger.LogInformation("DNS Server starting on {Address}:{Port} (UDP + TCP)",
                _options.DnsBindAddress, _options.DnsPort);

            var udpTask = RunUdpServerAsync(stoppingToken);
            var tcpTask = RunTcpServerAsync(stoppingToken);

            await Task.WhenAll(udpTask, tcpTask);
        }
        catch (OperationCanceledException) { /* Normal shutdown */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fatal error in DNS Server");
        }
        finally
        {
            _logger.LogInformation("DNS Server stopped.");
        }
    }

    // ===================== UDP Server =====================

    private async Task RunUdpServerAsync(CancellationToken ct)
    {
        try
        {
            var endpoint = new IPEndPoint(IPAddress.Parse(_options.DnsBindAddress), _options.DnsPort);
            using var udpClient = new UdpClient(endpoint);

            _logger.LogInformation("UDP DNS listener active on {Endpoint}", endpoint);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var result = await udpClient.ReceiveAsync(ct);
                    _ = HandleUdpRequestAsync(udpClient, result);
                }
                catch (OperationCanceledException) { break; }
                catch (SocketException ex)
                {
                    _logger.LogError(ex, "UDP socket error");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected UDP error");
                }
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            _logger.LogError(
                "UDP port {Port} is already in use! On Ubuntu, run: sudo dotnet run -- --install",
                _options.DnsPort);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start UDP DNS listener");
        }
    }

    private async Task HandleUdpRequestAsync(UdpClient client, UdpReceiveResult result)
    {
        try
        {
            var query = DnsPacketHandler.ParseQuery(result.Buffer, result.Buffer.Length);
            if (query is null) return;

            long reqNum = Interlocked.Increment(ref _requestCount);
            _logger.LogDebug("Request #{Num} from {Remote} > {Name}",
                reqNum, result.RemoteEndPoint.Address, query.Value.Name);

            byte[] response = BuildResponse(query.Value, result.RemoteEndPoint.Address.ToString());
            await client.SendAsync(response, response.Length, result.RemoteEndPoint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling UDP request from {Remote}", result.RemoteEndPoint);
        }
    }

    // ===================== TCP Server =====================

    private async Task RunTcpServerAsync(CancellationToken ct)
    {
        TcpListener? listener = null;
        try
        {
            listener = new TcpListener(IPAddress.Parse(_options.DnsBindAddress), _options.DnsPort);
            listener.Start();

            _logger.LogInformation("TCP DNS listener active on port {Port}", _options.DnsPort);

            ct.Register(() => { try { listener.Stop(); } catch { } });

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await listener.AcceptTcpClientAsync(ct);
                    _ = HandleTcpClientAsync(tcpClient);
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "TCP accept error");
                }
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            _logger.LogError(
                "TCP port {Port} is already in use! On Ubuntu, run: sudo dotnet run -- --install",
                _options.DnsPort);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start TCP DNS listener");
        }
    }

    private async Task HandleTcpClientAsync(TcpClient tcpClient)
    {
        try
        {
            using var client = tcpClient;
            client.ReceiveTimeout = 5000;
            var stream = client.GetStream();

            // DNS over TCP: 2-byte big-endian length prefix
            var lengthBuf = new byte[2];
            await stream.ReadExactlyAsync(lengthBuf);
            int msgLen = (lengthBuf[0] << 8) | lengthBuf[1];

            if (msgLen <= 0 || msgLen > 4096) return;

            var msgBuf = new byte[msgLen];
            await stream.ReadExactlyAsync(msgBuf);

            var query = DnsPacketHandler.ParseQuery(msgBuf, msgLen);
            if (query is null) return;

            var remoteEp = (IPEndPoint?)client.Client.RemoteEndPoint;
            long reqNum = Interlocked.Increment(ref _requestCount);
            _logger.LogDebug("TCP Request #{Num} from {Remote} > {Name}",
                reqNum, remoteEp?.Address, query.Value.Name);

            byte[] response = BuildResponse(query.Value, remoteEp?.Address.ToString() ?? "?");

            // Write 2-byte length prefix + response
            var tcpResponse = new byte[2 + response.Length];
            tcpResponse[0] = (byte)(response.Length >> 8);
            tcpResponse[1] = (byte)(response.Length & 0xFF);
            Buffer.BlockCopy(response, 0, tcpResponse, 2, response.Length);

            await stream.WriteAsync(tcpResponse);
        }
        catch (System.IO.EndOfStreamException)
        {
            // Ignore: TCP client connected but dropped the connection early (e.g. port scanner)
        }
        catch (System.IO.IOException)
        {
            // Ignore: Socket unexpectedly closed
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling TCP DNS client");
        }
    }

    // ===================== Response Builder =====================

    private byte[] BuildResponse(DnsQuery query, string clientAddress)
    {
        try
        {
            var pool = _ipPool.FindPool(query.Name);

            if (pool is not null && query.Type == 1) // Type A
            {
                var ips = pool.GetBestIps(_options.MaxAnswerCount, _options.RoutingMode);
                if (ips.Count > 0)
                {
                    _logger.LogInformation("🎯 [DNS Query] User IP: {Client} requested '{Domain}' -> Assigned: {Addresses}",
                        clientAddress, pool.Domain, string.Join(", ", ips));
                    return DnsPacketHandler.BuildAResponse(query, ips, _options.ResponseTtlSeconds);
                }

                _logger.LogWarning("  -> {Client} < [{Domain}] No healthy IPs available!",
                    clientAddress, pool.Domain);
            }
            else
            {
                _logger.LogDebug("  -> {Client} < No matching domain for '{Name}'",
                    clientAddress, query.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error building DNS response for {Name}", query.Name);
        }

        return DnsPacketHandler.BuildEmptyResponse(query);
    }
}
