
using System.Diagnostics;
using System.Text.Json;
using TrivyService.Application.Interfaces;
using TrivyService.Domain.Models;

namespace TrivyService.Infrastructure.Trivy;

public class TrivyScanService : ITrivyService
{
    private readonly ILogger<TrivyScanService> _logger;

    private static readonly Dictionary<string, string> OwaspMappings =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["CWE-22"] = "A01:2021 - Broken Access Control",
            ["CWE-23"] = "A01:2021 - Broken Access Control",
            ["CWE-36"] = "A01:2021 - Broken Access Control",

            ["CWE-311"] = "A02:2021 - Cryptographic Failures",
            ["CWE-312"] = "A02:2021 - Cryptographic Failures",
            ["CWE-319"] = "A02:2021 - Cryptographic Failures",
            ["CWE-326"] = "A02:2021 - Cryptographic Failures",
            ["CWE-327"] = "A02:2021 - Cryptographic Failures",

            ["CWE-78"] = "A03:2021 - Injection",
            ["CWE-79"] = "A03:2021 - Injection",
            ["CWE-89"] = "A03:2021 - Injection",
            ["CWE-94"] = "A03:2021 - Injection",

            ["CWE-400"] = "A04:2021 - Insecure Design",

            ["CWE-434"] = "A05:2021 - Security Misconfiguration",
            ["CWE-611"] = "A05:2021 - Security Misconfiguration",

            ["CWE-287"] = "A07:2021 - Identification and Authentication Failures",
            ["CWE-306"] = "A07:2021 - Identification and Authentication Failures",
            ["CWE-522"] = "A07:2021 - Identification and Authentication Failures",

            ["CWE-502"] = "A08:2021 - Software and Data Integrity Failures",

            ["CWE-918"] = "A10:2021 - Server-Side Request Forgery"
        };

    public TrivyScanService(ILogger<TrivyScanService> logger)
    {
        _logger = logger;
    }

    public async Task<ScanResult> ScanAsync(
        ScanRequest request,
        CancellationToken cancellationToken = default)
    {
        var result = new ScanResult
        {
            AssetId = request.AssetId,
            ScanRunId = request.ScanRunId,
            Scanner = "Trivy",
            Source = request.Source
        };

        if (string.IsNullOrWhiteSpace(request.Source))
        {
            result.Success = false;
            result.Error = "Repository source is required.";
            return result;
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "docker",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("--rm");
            startInfo.ArgumentList.Add("aquasec/trivy:latest");
            startInfo.ArgumentList.Add("repo");
            startInfo.ArgumentList.Add("--format");
            startInfo.ArgumentList.Add("json");
            startInfo.ArgumentList.Add(request.Source);

            using var process = new Process
            {
                StartInfo = startInfo
            };

            process.Start();

            var outputTask =
                process.StandardOutput.ReadToEndAsync(cancellationToken);

            var errorTask =
                process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken);

            var output = await outputTask;
            var error = await errorTask;

            if (process.ExitCode != 0)
            {
                result.Success = false;
                result.Error = string.IsNullOrWhiteSpace(error)
                    ? $"Trivy exited with code {process.ExitCode}."
                    : error;

                return result;
            }

            result.Output = output;
            result.Error = error;
            result.Findings = ParseFindings(output);
            result.Success = true;

            _logger.LogInformation(
                "Trivy scan completed. AssetId: {AssetId}, Findings: {Count}",
                request.AssetId,
                result.Findings.Count);

            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Trivy scan failed.");

            result.Success = false;
            result.Error = ex.Message;

            return result;
        }
    }

    private static List<ScanFinding> ParseFindings(string output)
    {
        var findings = new List<ScanFinding>();

        if (string.IsNullOrWhiteSpace(output))
        {
            return findings;
        }

        using var document = JsonDocument.Parse(output);

        var root = document.RootElement;

        if (!root.TryGetProperty("Results", out var results) ||
            results.ValueKind != JsonValueKind.Array)
        {
            return findings;
        }

        foreach (var scanResult in results.EnumerateArray())
        {
            var target = GetString(scanResult, "Target");

            if (!scanResult.TryGetProperty(
                    "Vulnerabilities", out var vulnerabilities) ||
                vulnerabilities.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var vulnerability in vulnerabilities.EnumerateArray())
            {
                var vulnerabilityId =
                    GetString(vulnerability, "VulnerabilityID");

                var title =
                    GetString(vulnerability, "Title");

                var description =
                    GetString(vulnerability, "Description");

                var cweIds =
                    GetStringArray(vulnerability, "CweIDs");

                var owaspCategories =
                    GetOwaspCategories(cweIds);

                findings.Add(new ScanFinding
                {
                    CheckId = vulnerabilityId,
                    Identifier = vulnerabilityId,
                    IdentifierType = GetIdentifierType(vulnerabilityId),

                    Title = string.IsNullOrWhiteSpace(title)
                        ? vulnerabilityId
                        : title,

                    Path = target,

                    Message = string.IsNullOrWhiteSpace(description)
                        ? title
                        : description,

                    Category = "SCA",
                    Severity = GetString(vulnerability, "Severity"),

                    PackageName = GetString(vulnerability, "PkgName"),
                    InstalledVersion = GetString(vulnerability, "InstalledVersion"),
                    FixedVersion = GetString(vulnerability, "FixedVersion"),

                    Status = "Open",

                    Cwe = string.Join(", ", cweIds),
                    Owasp = string.Join(", ", owaspCategories),

                    Reference = GetString(vulnerability, "PrimaryURL")
                });
            }
        }

        return findings;
    }

    private static List<string> GetStringArray(
        JsonElement element,
        string propertyName)
    {
        var values = new List<string>();

        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.Array)
        {
            return values;
        }

        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var value = item.GetString();

            if (!string.IsNullOrWhiteSpace(value))
            {
                values.Add(value);
            }
        }

        return values.Distinct(
            StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<string> GetOwaspCategories(
        List<string> cweIds)
    {
        var categories = new List<string>();

        foreach (var cweId in cweIds)
        {
            if (OwaspMappings.TryGetValue(cweId, out var category) &&
                !categories.Contains(category))
            {
                categories.Add(category);
            }
        }

        return categories;
    }

    private static string GetIdentifierType(string identifier)
    {
        if (identifier.StartsWith(
                "CVE-", StringComparison.OrdinalIgnoreCase))
        {
            return "CVE";
        }

        if (identifier.StartsWith(
                "GHSA-", StringComparison.OrdinalIgnoreCase))
        {
            return "GHSA";
        }

        return "Other";
    }

    private static string GetString(
        JsonElement element,
        string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : string.Empty;
    }
}
