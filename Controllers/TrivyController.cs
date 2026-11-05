
using Microsoft.AspNetCore.Mvc;
using TrivyService.Application.Interfaces;
using TrivyService.Domain.Models;

namespace TrivyService.Controllers;

[ApiController]
[Route("api/trivy")]
public class TrivyController : ControllerBase
{
    private readonly ITrivyService _trivyService;

    public TrivyController(ITrivyService trivyService)
    {
        _trivyService = trivyService;
    }

    [HttpPost("scan")]
    public async Task<IActionResult> Scan(
        [FromBody] ScanRequest request,
        CancellationToken cancellationToken)
    {
        var result =
            await _trivyService.ScanAsync(request, cancellationToken);

        return Ok(result);
    }
}
