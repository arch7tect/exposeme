# Why I Built ExposeME — My Quiet Rebellion Against Subscriptions

Every time I worked on a small bot, webhook, or quick demo, I hit the same wall:  
**how do I make my local app visible to the world without spending half a day on setup?**

You know the story. You just want to test a webhook or show a client what you built.  
But suddenly you’re wrestling with ports, certificates, random subdomains, and firewalls.  
It’s like needing a pilot’s license just to send a postcard.

For years, I used **ngrok**. It’s solid. But one day I needed to run **two tunnels** at once — one for a WhatsApp bot and another for an internal API.  
That’s when I discovered the free plan only allows one tunnel.  
Fair enough — I upgraded to the $10/month plan, used it for a week, and moved on.

Then, of course, I forgot to cancel.  
Months later, there it was — the quiet little subscription that keeps renewing while you’re not looking.

And it wasn’t just me. My teammates needed tunnels too.  
We could either share one account (and break each other’s sessions) or each pay separately.  
All that for a few hours of testing here and there.  
It felt silly.

At some point, I thought: *why am I renting a tunnel?*  
I wanted something that just worked —
- one command,
- my local app is online over HTTPS,
- and no monthly subscription quietly nibbling at my wallet.

So I built **ExposeME**.  
Not as a “startup” or a “competitor,” but as a weekend experiment that got out of hand.  
It runs anywhere, you own it, and it doesn’t need a paid plan to do its job.

I also used it as a chance to learn **Rust**, which turned out to be perfect for something this fast and network-heavy.  
Somewhere along the way, I added a small **embedded dashboard** — just enough to see requests, metrics, and certificates — without turning it into a cloud platform.  
No user accounts, no “Pro” tier, no marketing emails. Just a clean little control panel built into your own server.

I don’t run dozens of tunnels.  
Most of the time, it’s just one for a quick test — sometimes two when I’m juggling different bots or APIs.  
But that’s exactly the point: I can spin them up whenever I need to, without thinking about billing cycles or limits.

ExposeME is open-source (MIT license), and you can run it on a $5 VPS if you like.  
That’s it. No hidden fees, no nonsense.

ExposeME is a tunnel for people who don’t want to think about tunnels.

---

**GitHub:** [https://github.com/arch7tect/exposeme](https://github.com/arch7tect/exposeme)  
**License:** MIT
