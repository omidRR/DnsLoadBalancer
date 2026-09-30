using System.Collections.Generic;

namespace DnsLoadBalancer.Models;

/// <summary>Configuration for a single domain and its associated IP list file.</summary>
public sealed class DomainConfig
{
    public string Name { get; set; } = "";
    public string IpListFilePath { get; set; } = "";
}

public sealed class DnsLoadBalancerOptions
{
	public int DnsPort { get; set; } = 53;

	public string DnsBindAddress { get; set; } = "0.0.0.0";

	public int TlsCheckIntervalSeconds { get; set; } = 26;

	public int TlsTimeoutMs { get; set; } = 5000;

	public int UploadTestSizeKB { get; set; } = 500;

	public int TlsPort { get; set; } = 443;

	public int MaxConcurrentChecks { get; set; } = 10;

	public int MaxHealthyIpsTarget { get; set; }

	public int MaxAnswerCount { get; set; } = 3;

	public uint ResponseTtlSeconds { get; set; } = 60u;

	public string TlsCheckDomain { get; set; } = "cloudflare.com";

	public bool ValidateTlsCertificate { get; set; }

	public string RoutingMode { get; set; } = "LowestPing";

	public List<DomainConfig> Domains { get; set; } = new List<DomainConfig>();
}
