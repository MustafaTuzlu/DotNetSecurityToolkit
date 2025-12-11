using DotNetSecurityToolkit.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Caching.Memory;

namespace DotNetSecurityToolkit.Middleware.RateLimiting;

/// <summary>
/// Lightweight in-memory rate limiting middleware using a sliding window per remote IP.
/// </summary>
public sealed class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly RateLimitingOptions _options;
    private readonly IMemoryCache _cache;

    public RateLimitingMiddleware(RequestDelegate next, IOptions<RateLimitingOptions> options, IMemoryCache cache)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.Enabled)
        {
            await _next(context);
            return;
        }

        var identifier = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
        var window = TimeSpan.FromSeconds(_options.WindowSeconds);
        var now = DateTimeOffset.UtcNow;

        var counter = _cache.GetOrCreate(identifier, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = window;
            return new SlidingWindowCounter(now, window);
        })!;

        lock (counter)
        {
            counter.Prune(now);
            if (counter.Count >= _options.RequestsPerWindow)
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                if (_options.EmitRetryAfterHeader)
                {
                    context.Response.Headers.RetryAfter = Math.Ceiling(counter.GetRetryAfter(now).TotalSeconds).ToString();
                }

                return;
            }

            counter.Register(now);
        }

        await _next(context);
    }

    private sealed class SlidingWindowCounter
    {
        private readonly Queue<DateTimeOffset> _timestamps = new();
        private readonly TimeSpan _window;

        public SlidingWindowCounter(DateTimeOffset now, TimeSpan window)
        {
            _window = window;
            _timestamps.Enqueue(now);
        }

        public int Count => _timestamps.Count;

        public void Register(DateTimeOffset timestamp)
        {
            _timestamps.Enqueue(timestamp);
            Prune(timestamp);
        }

        public void Prune(DateTimeOffset now)
        {
            while (_timestamps.Count > 0 && now - _timestamps.Peek() > _window)
            {
                _timestamps.Dequeue();
            }
        }

        public TimeSpan GetRetryAfter(DateTimeOffset now)
        {
            if (_timestamps.Count == 0)
            {
                return TimeSpan.Zero;
            }

            var earliest = _timestamps.Peek();
            var elapsed = now - earliest;
            return elapsed > _window ? TimeSpan.Zero : _window - elapsed;
        }
    }
}
