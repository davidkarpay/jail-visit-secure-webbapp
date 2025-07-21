# DNS Configuration for GitHub Pages Custom Domain

## Required DNS Records in Cloudflare Dashboard

Go to: https://dash.cloudflare.com → Your Domain (karpaylegal.com) → DNS → Records

### Add These Records:

1. **CNAME Record for Subdomain**
   - Type: `CNAME`
   - Name: `jailvisit`
   - Content: `davidkarpay.github.io`
   - Proxy status: `Proxied` (orange cloud)
   - TTL: `Auto`

2. **GitHub Pages IP Addresses (A Records for Apex Domain - Optional)**
   If you also want the apex domain to work, add these A records:
   - Type: `A`, Name: `@`, Content: `185.199.108.153`, Proxy: `Proxied`
   - Type: `A`, Name: `@`, Content: `185.199.109.153`, Proxy: `Proxied`
   - Type: `A`, Name: `@`, Content: `185.199.110.153`, Proxy: `Proxied`
   - Type: `A`, Name: `@`, Content: `185.199.111.153`, Proxy: `Proxied`

### Result:
- Your app will be accessible at: `https://jailvisit.karpaylegal.com`
- Your Worker API remains at: `https://jail-visit-api.dlkarpay.workers.dev`

## Verification Steps:

1. Wait 5-10 minutes for DNS propagation
2. Check GitHub Pages settings - should show green checkmark
3. Visit https://jailvisit.karpaylegal.com
4. Verify HTTPS certificate is working

## If You Get SSL/TLS Errors:

In Cloudflare Dashboard → SSL/TLS:
- Set SSL/TLS encryption mode to "Full (strict)"
- Enable "Always Use HTTPS"
