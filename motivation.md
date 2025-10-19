# why i built exposeme

i was building a whatsapp bot one night and hit the same stupid wall again —  
how do i get my local server online fast enough for webhook testing *without paying someone for the privilege*?

i’ve used ngrok for years. it’s great.  
but i needed two tunnels that day — one for the bot, one for the backend — and the free plan only allows one.  
fine, i thought, i’ll grab the paid plan for a month.

that was three months of billing cycles ago.

and of course, my teammates also needed tunnels.  
we either shared one account (and kept breaking each other’s sessions) or paid separately.  
all this for maybe a few hours of testing a month.  
it just didn’t make sense anymore.

so i built **exposeme**.

not as a startup or a product — just a weekend side thing that got a bit too comfortable.  
it runs on your own server, uses real ssl certs, and does the job without making you sign up for anything.

i wrote it in rust because i wanted to learn rust, and i kept it small on purpose.  
there’s a simple embedded dashboard for logs and cert info, but that’s it.  
no cloud accounts, no “pro” tier, no upsell page.

most of the time i only need one tunnel, sometimes two.  
and it’s nice knowing i can spin them up whenever i want, no subscriptions, no reminders to cancel.

that’s really all it is — a way to avoid overpaying for something that should’ve been simple.  
and maybe a reminder to build your own tools once in a while, if only to stop being annoyed.

---

[github.com/arch7tect/exposeme](https://github.com/arch7tect/exposeme)
