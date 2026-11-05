namespace TrivyService.Domain.Models;

public class ScanFinding
{
    public string CheckId { get; set; } = string.Empty;
    public string Identifier { get; set; } = string.Empty;
    public string IdentifierType { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public int? StartLine { get; set; }
    public int? StartColumn { get; set; }
    public int? EndLine { get; set; }
    public int? EndColumn { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string PackageName { get; set; } = string.Empty;
    public string InstalledVersion { get; set; } = string.Empty;
    public string FixedVersion { get; set; } = string.Empty;
    public string Status { get; set; } = "Open";
    public string Confidence { get; set; } = string.Empty;
    public string Impact { get; set; } = string.Empty;
    public string Cwe { get; set; } = string.Empty;
    public string Owasp { get; set; } = string.Empty;
    public string VulnerabilityClass { get; set; } = string.Empty;
    public string Reference { get; set; } = string.Empty;
}