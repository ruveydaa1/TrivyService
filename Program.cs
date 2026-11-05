
using TrivyService.Application.Interfaces;
using TrivyService.Infrastructure.Trivy;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddControllers();

// Trivy service
builder.Services.AddSingleton<ITrivyService, TrivyScanService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Internal API Key protection
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/trivy/scan"))
    {
        var configuredApiKey =
            app.Configuration["InternalApiKey"];

        var requestApiKey =
            context.Request.Headers["X-Internal-Api-Key"]
                .FirstOrDefault();

        if (string.IsNullOrWhiteSpace(configuredApiKey) ||
            requestApiKey != configuredApiKey)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;

            await context.Response.WriteAsync(
                "Unauthorized: Invalid or missing API key.");

            return;
        }
    }

    await next();
});

app.MapControllers();

app.Run();
