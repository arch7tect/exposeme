# Why I Built ExposeME: The Self-Hosted Alternative to ngrok for WhatsApp and Telegram Bots

As a developer working on WhatsApp bots, webhook integrations, and client demos, I kept running into the same problem: **how do I quickly expose my local development server to the internet with a clean, HTTPS URL?**

Sure, there are tools like wstunnel, ngrok, and others. But they all fell short in different ways. Here's why I built ExposeME, and why it might be exactly what you need too.

## The ngrok Problem: Great Tool, Expensive Mistake

I used ngrok for years. It's a fantastic tool that just works. Until I needed two webhook endpoints running simultaneously for a client project.

The free tier only allows one tunnel. No problem, I'll upgrade to the paid plan at $10/month. I needed it for maybe a week of development, then a few debugging sessions over the next year. **I forgot to cancel.**

A year later, I checked my credit card statement: **\$120 spent on a tool where I used the paid features maybe 2-3 times that year.** Most months, that $10 charge was for a service sitting idle.

Then I realized if my teammates had the same webhook testing needs, we'd face another problem. With ngrok, each person either needs their own paid subscription or we all share one account (coordination nightmare). Either way, we'd be paying monthly fees for a tool the team uses sporadically.

Don't get me wrong - ngrok is worth every penny if you use it regularly. But for occasional webhook development across a team? That's hundreds of dollars we could've spent on better tools, training, or team lunches.

I needed:
- Multiple tunnels without subscription tiers
- Entire team can use it without per-seat pricing
- Pay once (or free), use anytime
- Own my infrastructure, control my costs

That's when I started looking at alternatives. I also wanted to learn Rust, which seemed perfect for building a high-performance networking tool. So I built ExposeME.

## The Problem with Generic Tunneling Tools

Let's say you're building a WhatsApp bot. Meta requires:
- HTTPS with a valid SSL certificate (not self-signed)
- A publicly accessible webhook URL
- Fast, reliable responses for verification

With a generic tunneling tool like wstunnel, here's what your setup looks like:

```bash
# On your VPS
sudo apt install nginx certbot
sudo certbot --nginx -d yourdomain.com
# Configure NGINX reverse proxy
# Setup wstunnel server
# Configure firewall rules
# Debug connection issues

# On your local machine
wstunnel client -L 8080:localhost:3000 wss://yourdomain.com:9000

# Configure WhatsApp webhook
Webhook URL: https://yourdomain.com/webhook
# (but you need NGINX to route this to port 8080...)
```

**Result:** Significant DevOps work before you can write a single line of bot code.

## What Developers Actually Need

After building dozens of webhook integrations, I realized what developers really need:

1. **One command to go from localhost to HTTPS**
2. **Clean, shareable URLs** (not `http://server:8080`)
3. **Valid SSL certificates** (automatic, not manual)
4. **Multiple environments** (dev, staging, client-demo)
5. **Visibility** (what requests are coming in?)
6. **Zero infrastructure setup** (I want to code, not configure NGINX)

None of the existing tools checked all these boxes.

## Introducing ExposeME

ExposeME is built specifically for web developers who need to expose HTTP services. Here's the same WhatsApp bot setup:

```bash
# That's it. One command.
docker run -it --rm ghcr.io/arch7tect/exposeme-client:latest \
  --server-url "wss://exposeme.org/tunnel-ws" \
  --token "uoINplvTSD3z8nOuzcDC5JDq41sf4GGELoLELBymXTY=" \
  --tunnel-id "whatsapp-bot" \
  --local-target "http://localhost:3000"

# Configure WhatsApp webhook
Webhook URL: https://whatsapp-bot.exposeme.org/webhook
# Valid SSL ✓ Clean URL ✓ Works immediately ✓
```

## Real-World Use Cases

### 1. WhatsApp/Telegram Bot Development

```bash
# Development bot
--tunnel-id "wa-dev" --local-target "http://localhost:3000"
# https://wa-dev.exposeme.org/webhook

# Staging bot
--tunnel-id "wa-staging" --local-target "http://localhost:3001"
# https://wa-staging.exposeme.org/webhook

# Each gets a clean URL. No port conflicts. No NGINX config.
```

### 2. Client Demos

```bash
# Friday afternoon: "Can you show us what you've built?"
--tunnel-id "client-demo" --local-target "http://localhost:3000"

# Send them: https://client-demo.yourdomain.com
# Professional URL. Valid SSL. Works on mobile.
```

### 3. Webhook Testing

```bash
# Testing GitHub webhooks, payment processors, OAuth callbacks
--tunnel-id "webhooks" --local-target "http://localhost:4000"
# https://webhooks.yourdomain.com/github
# https://webhooks.yourdomain.com/stripe
# https://webhooks.yourdomain.com/oauth/callback
```

### 4. Mobile App Development

```bash
# Backend API for mobile testing
--tunnel-id "api" --local-target "http://localhost:8000"
# https://api.yourdomain.com
# Test from real devices over HTTPS (required for many APIs)
```

## How ExposeME is Different

### Cost Model

**ngrok:**
- Free: 1 tunnel, random URLs, rate limits
- $10/month: Multiple tunnels, custom domains, reserved domains
- Keeps charging even when you're not using it

**wstunnel:** Free, but requires VPS ($5-10/month) + time investment

**ExposeME:**
- Free public test server (unlimited tunnels)
- Or deploy your own once: VPS cost only ($5/month), no recurring service fees
- Use it 100 times or 2 times a year - same cost

### Built for HTTP, Not Generic TCP

**ngrok:** HTTP tunneling with great UX, but subscription-based
**wstunnel:** Generic TCP/UDP tunnel that happens to work with HTTP
**ExposeME:** Purpose-built for HTTP services with:
- Native HTTP request/response streaming
- Server-Sent Events (SSE) support
- WebSocket proxying
- Large file upload/download optimization

### Automatic SSL Management

**ngrok:** Managed SSL (included in service)
**wstunnel:** Self-signed certs by default, manual Let's Encrypt setup
**ExposeME:**
- Automatic Let's Encrypt certificates
- Wildcard certificate support
- DNS provider integration (Cloudflare, DigitalOcean, Azure, Hetzner)
- Auto-renewal every 90 days

### Developer-Friendly URLs

**ngrok:** Custom domains on paid plans ($10/month+)
**wstunnel:** Port-based (`http://server:8080`)
**ExposeME:**
- Subdomain routing: `https://app.yourdomain.com`
- Path-based routing: `https://yourdomain.com/app/`
- Clean, shareable, professional
- Your own domain, full control

### Real-Time Visibility

**ngrok:** Excellent web UI with request inspection (included)
**wstunnel:** CLI-only, basic logging
**ExposeME:**
- Modern web dashboard (Rust WASM + Leptos)
- Real-time metrics and traffic visualization
- Per-tunnel analytics
- Certificate management UI
- Live request/response monitoring

### Multiple Tunnels

**ngrok:** 1 tunnel free, pay $10/month for more
**wstunnel:** Unlimited, but manual setup per tunnel
**ExposeME:** Unlimited tunnels, any time
- Free test server: unlimited
- Your own server: unlimited
- Each tunnel gets unique ID and URL

## The Technical Foundation

ExposeME is written in Rust with:
- Binary protocol over WebSocket for efficiency
- Automatic reconnection with configurable retry
- Token-based authentication
- Multi-tenant architecture (multiple tunnels per domain)
- HTTP streaming without memory buffering

It's fast, reliable, and handles everything from simple demos to production webhook endpoints.

## When to Use wstunnel Instead

To be fair, wstunnel is better if you need:
- Non-HTTP protocols (SSH tunneling, VPN, databases)
- UDP support
- Raw TCP performance
- Aggressive firewall/DPI bypass

But for 95% of web development use cases, you don't need those features. You need:
- `http://localhost:3000` → `https://app.yourdomain.com`
- In one command
- With valid SSL
- Right now

That's ExposeME.

## Try It Yourself

**Test server (no setup required):**

```bash
docker run -it --rm ghcr.io/arch7tect/exposeme-client:latest \
  --server-url "wss://exposeme.org/tunnel-ws" \
  --token "uoINplvTSD3z8nOuzcDC5JDq41sf4GGELoLELBymXTY=" \
  --tunnel-id "my-test" \
  --local-target "http://localhost:3000"
```

Your service is now at: `https://my-test.exposeme.org/`

**Your own server (production-ready):**

```bash
# On VPS
git clone https://github.com/arch7tect/exposeme.git
cd exposeme
# Configure .env with your domain
docker compose up -d

# On your dev machine
docker run -it --rm ghcr.io/arch7tect/exposeme-client:latest \
  --server-url "wss://yourdomain.com/tunnel-ws" \
  --token "your_token" \
  --tunnel-id "my-app" \
  --local-target "http://localhost:3000"
```

Your service is now at: `https://my-app.yourdomain.com/`

## The Bottom Line

I built ExposeME because I was tired of:
- **Paying $120/year for a tool I used 2-3 times**
- **Fighting infrastructure when I should be building features**
- **Choosing between "easy but expensive" (ngrok) or "cheap but complex" (wstunnel)**

Every hour spent configuring NGINX, debugging SSL certificates, or wrestling with port forwarding is an hour not spent on your actual product. Every dollar spent on subscriptions for services you rarely use is money wasted.

**ExposeME handles the boring infrastructure stuff so you can focus on what matters: building great software.**

It's completely free and open-source (MIT license). Use the public test server, or deploy your own on a VPS. Use it as much or as little as you need. No monthly charges for idle services.

If you're a web developer who needs to expose local services, try ExposeME. It might save you hundreds of dollars and hours every year.

---

**Links:**
- GitHub: https://github.com/arch7tect/exposeme
- Documentation: Full setup guide in README
- License: MIT