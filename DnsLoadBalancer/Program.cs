using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using DnsLoadBalancer.Models;
using DnsLoadBalancer.Services;

namespace DnsLoadBalancer;

public class Program
{
    public static async Task Main(string[] args)
    {
        try
        {
            if (args.Contains("--install"))
            {
                await InstallAsSystemdServiceAsync();
                return;
            }

            var builder = Host.CreateApplicationBuilder(args);

            // Enable systemd integration
            builder.Services.AddSystemd();

            // Bind configuration section to strongly-typed options
            builder.Services.Configure<DnsLoadBalancerOptions>(
                builder.Configuration.GetSection("DnsLoadBalancer"));

            // Register services
            builder.Services.AddSingleton<IpPoolManager>();
            builder.Services.AddHostedService<TlsHealthCheckService>();
            builder.Services.AddHostedService<DnsServerService>();

            var host = builder.Build();

            // ===== Startup Banner =====
            var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
            var options = host.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<DnsLoadBalancerOptions>>().Value;

            logger.LogInformation("=============================================");
            logger.LogInformation("  DNS Load Balancer with TLS Health Check");
            logger.LogInformation("  DNS Port: {Port} (UDP + TCP)", options.DnsPort);
            logger.LogInformation("  Check Domain: {Domain}", options.TlsCheckDomain);
            logger.LogInformation("  Configured Domains:");
            foreach (var d in options.Domains)
            {
                logger.LogInformation("    - {Name} (IP List: {Path})", d.Name, d.IpListFilePath);
            }
            logger.LogInformation("=============================================");

            await host.RunAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fatal error on startup: {ex.Message}");
        }
    }

    private static async Task InstallAsSystemdServiceAsync()
    {
        try
        {
            Console.WriteLine("Starting installation process on Ubuntu...");

            // 1. Free port 53 by disabling systemd-resolved
            Console.WriteLine("Stopping and disabling systemd-resolved to free port 53...");
            await RunCommandAsync("systemctl", "stop systemd-resolved");
            await RunCommandAsync("systemctl", "disable systemd-resolved");

            // Fix resolv.conf if we disabled systemd-resolved
            try
            {
                if (File.Exists("/etc/resolv.conf"))
                {
                    File.Delete("/etc/resolv.conf");
                }
                await File.WriteAllTextAsync("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
                Console.WriteLine("Updated /etc/resolv.conf to use public DNS.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not update resolv.conf: {ex.Message}");
            }

            // 2. Create systemd service file
            string serviceName = "dnsloadbalancer.service";
            string servicePath = $"/etc/systemd/system/{serviceName}";
            string appPath = Process.GetCurrentProcess().MainModule?.FileName ?? throw new Exception("Could not find executable path");
            string appDir = Path.GetDirectoryName(appPath) ?? "/";

            string serviceContent = $"""
            [Unit]
            Description=DNS Load Balancer with TLS Health Check
            After=network.target

            [Service]
            Type=notify
            ExecStart={appPath}
            WorkingDirectory={appDir}
            Restart=always
            RestartSec=5
            Environment=DOTNET_ENVIRONMENT=Production

            [Install]
            WantedBy=multi-user.target
            """;

            await File.WriteAllTextAsync(servicePath, serviceContent);
            Console.WriteLine($"Created systemd service file at {servicePath}");

            // 3. Reload systemd, enable and start service
            Console.WriteLine("Reloading systemd daemon...");
            await RunCommandAsync("systemctl", "daemon-reload");

            Console.WriteLine("Enabling service to start on boot...");
            await RunCommandAsync("systemctl", $"enable {serviceName}");

            Console.WriteLine("Starting service...");
            await RunCommandAsync("systemctl", $"restart {serviceName}");

            Console.WriteLine("Installation successful! Showing live logs...");
            Console.WriteLine("Press Ctrl+C to exit log view (the service will keep running in the background).");
            
            // Show logs
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = "journalctl",
                Arguments = $"-u {serviceName} -f",
                UseShellExecute = false
            });
            
            if (process != null)
            {
                await process.WaitForExitAsync();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Installation failed: {ex.Message}");
            Console.WriteLine("Make sure you are running this command as root (sudo).");
        }
    }

    private static async Task RunCommandAsync(string command, string arguments)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };

            process.Start();
            await process.WaitForExitAsync();

            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();

            if (!string.IsNullOrWhiteSpace(output))
            {
                Console.WriteLine($"[Output] {output.Trim()}");
            }
            if (process.ExitCode != 0 && !string.IsNullOrWhiteSpace(error))
            {
                Console.WriteLine($"[Warning] {error.Trim()}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to execute {command} {arguments}: {ex.Message}");
        }
    }
}
