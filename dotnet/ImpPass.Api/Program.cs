using System.Text.Json.Serialization;
using Google.Cloud.Firestore;
using ImpPass.Api;

var builder = WebApplication.CreateBuilder(args);
var projectId = builder.Configuration["GoogleCloud:ProjectId"]
    ?? Environment.GetEnvironmentVariable("GOOGLE_CLOUD_PROJECT");

if (string.IsNullOrWhiteSpace(projectId))
    throw new InvalidOperationException(
        "Set GoogleCloud:ProjectId or GOOGLE_CLOUD_PROJECT before starting the API.");

builder.Services.AddSingleton(FirestoreDb.Create(projectId));
builder.Services.AddSingleton<ImpPassStore>();

var origins = new List<string> { "http://localhost:9000", "http://localhost:4200" };
var frontendUrl = Environment.GetEnvironmentVariable("FRONTEND_URL");
if (!string.IsNullOrWhiteSpace(frontendUrl))
    origins.Add(frontendUrl);

builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins(origins.Distinct().ToArray())
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials()
        .WithExposedHeaders("Session")));

var app = builder.Build();

app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (ApiException ex)
    {
        context.Response.StatusCode = ex.StatusCode;
        await context.Response.WriteAsJsonAsync(new { message = ex.Message });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Unhandled API error");
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(new { message = "Something went wrong." });
        }
    }
});

app.UseCors();

app.MapGet("/", () => Results.Ok(new { message = "The API is UP!" }));

app.MapPost("/register", async (RegisterRequest request, ImpPassStore store) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
        throw new ApiException(400, "Email and password are required.");

    await store.RegisterAsync(request.Email.Trim(), request.Password);
    return Results.Ok(new { message = "User Registered" });
});

app.MapGet("/identify", async (HttpContext context, ImpPassStore store) =>
{
    var session = await RequireSessionAsync(context, store);
    return Results.Ok(new { email = await store.GetEmailAsync(session.UserId) });
});

app.MapGet("/initSession", async (HttpContext context, ImpPassStore store) =>
{
    var session = await RequireSessionAsync(context, store);
    return Results.Ok(new { sessionID = session.SessionId });
});

app.MapGet("/validateSession", async (HttpContext context, ImpPassStore store) =>
{
    try
    {
        var session = await RequireSessionAsync(context, store, allowCredentials: false);
        return Results.Ok(new { sessionOk = session is not null });
    }
    catch (ApiException)
    {
        return Results.Ok(new { sessionOk = false });
    }
});

app.MapPut("/new", async (HttpContext context, ImpPassStore store, PasswordRequest request) =>
{
    var session = await RequireSessionAsync(context, store);
    if (string.IsNullOrWhiteSpace(request.Pid) || request.Password is null)
        throw new ApiException(400, "pID and password are required.");

    await store.CreatePasswordAsync(request.Pid, request.Password, session);
    return Results.Ok(new { message = "Created" });
});

app.MapGet("/password", async (HttpContext context, ImpPassStore store, string? pID) =>
{
    var session = await RequireSessionAsync(context, store);
    if (string.IsNullOrWhiteSpace(pID))
        throw new ApiException(400, "BAD REQUEST");

    if (pID == "all")
    {
        var all = await store.GetAllPasswordsAsync(session);
        return Results.Ok(all.Select(p => new { _id = p.Id, pID = p.Pid, password = p.Password }));
    }

    var item = await store.GetPasswordAsync(pID, session);
    return Results.Ok(new { password = item.Password, pid = pID });
});

app.MapGet("/delete", async (HttpContext context, ImpPassStore store, string? pID) =>
{
    var session = await RequireSessionAsync(context, store);
    if (string.IsNullOrWhiteSpace(pID))
        throw new ApiException(400, "pid empty");

    await store.DeletePasswordAsync(pID, session);
    return Results.Ok(new { message = $"Password with pID {pID} deleted" });
});

app.MapPut("/update", async (HttpContext context, ImpPassStore store, UpdatePasswordRequest request, string? pID) =>
{
    var session = await RequireSessionAsync(context, store);
    if (string.IsNullOrWhiteSpace(pID))
        throw new ApiException(400, "pID is required.");

    var changed = new List<string>();
    if (!string.IsNullOrEmpty(request.Password))
    {
        await store.UpdatePasswordAsync(pID, request.Password, session);
        changed.Add("password");
    }
    if (!string.IsNullOrEmpty(request.Pid))
    {
        await store.UpdatePidAsync(pID, request.Pid, session);
        changed.Add("pID");
    }
    if (changed.Count == 0)
        throw new ApiException(400, "Provide password and/or pID to update.");

    return Results.Ok(new { message = "Updated", updated = changed });
});

app.MapPut("/changePassword", async (HttpContext context, ImpPassStore store, ChangeMasterPasswordRequest request) =>
{
    var session = await RequireSessionAsync(context, store);
    if (string.IsNullOrEmpty(request.NewPassword))
        throw new ApiException(400, "newPassword is required.");

    var count = await store.ChangeMasterPasswordAsync(request.NewPassword, session);
    return Results.Ok(new { message = "Password Changed", recordsUpdated = count });
});

app.Run();

static async Task<SessionContext> RequireSessionAsync(
    HttpContext context,
    ImpPassStore store,
    bool allowCredentials = true)
{
    var authorization = context.Request.Headers.Authorization.ToString();
    if (authorization.StartsWith("Session ", StringComparison.OrdinalIgnoreCase))
    {
        var id = authorization["Session ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(id))
            throw new ApiException(400, "Session ID is invalid");

        return await store.GetSessionAsync(id)
            ?? throw new ApiException(401, "Session Expired");
    }

    if (!allowCredentials)
        throw new ApiException(401, "Session ID is invalid");

    var email = context.Request.Headers["email"].ToString();
    var password = context.Request.Headers["password"].ToString();
    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrEmpty(password))
        throw new ApiException(400, "Missing credential header");

    var session = await store.AuthenticateAsync(email.Trim(), password);
    context.Response.Headers["Session"] = session.SessionId;
    return session;
}

public sealed record RegisterRequest(
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("password")] string Password);

public sealed record PasswordRequest(
    [property: JsonPropertyName("pID")] string Pid,
    [property: JsonPropertyName("password")] string Password);

public sealed record UpdatePasswordRequest(
    [property: JsonPropertyName("pID")] string? Pid,
    [property: JsonPropertyName("password")] string? Password);

public sealed record ChangeMasterPasswordRequest(
    [property: JsonPropertyName("newPassword")] string NewPassword);
