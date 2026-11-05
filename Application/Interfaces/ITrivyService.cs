
using TrivyService.Domain.Models;

namespace TrivyService.Application.Interfaces;

public interface ITrivyService
{
    Task<ScanResult> ScanAsync(
        ScanRequest request,
        CancellationToken cancellationToken = default);
}
