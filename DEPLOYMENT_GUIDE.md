# Cloudflare Deployment Guide for Jail Visit Logger

This guide will help you deploy the multi-user version of Jail Visit Logger using Cloudflare Workers and Pages.

## Prerequisites

- Cloudflare account (free plan is sufficient)
- Node.js installed on your computer
- Git installed

## Step 1: Install Wrangler CLI

Wrangler is Cloudflare's command-line tool for managing Workers.

```bash
npm install -g wrangler
```

## Step 2: Login to Cloudflare

```bash
wrangler login
```

This will open a browser window for you to authenticate.

## Step 3: Create KV Namespaces

You need to create three KV namespaces for storing data:

### Option A: Using Cloudflare Dashboard (Easier)

1. Go to https://dash.cloudflare.com
2. Select your domain (karpaylegal.com)
3. Click on "Workers & Pages" in the left sidebar
4. Click on "KV" under "Storage"
5. Create three namespaces:
   - Name: `jail-visit-users` (for user accounts) (8b4c5fbf58864eea86bcc354de7a640f)
   - Name: `jail-visit-visits` (for visit data) (6bccdfc1b2d14c5dae6a1e6d2f19b37c)
   - Name: `jail-visit-settings` (for user settings) (efdb659f036d4b848c4db7bceef311ef)
6. Copy the ID of each namespace (you'll need these)

### Option B: Using Wrangler CLI

```bash
cd cloudflare-backend

# Create namespaces (updated syntax for newer Wrangler versions)
wrangler kv namespace create "USERS"
wrangler kv namespace create "VISITS"
wrangler kv namespace create "SETTINGS"
```

Copy the IDs that are output from these commands.

**Your created namespace IDs:**
- USERS: `cf359fa838de461b90d015512bc67051`
- VISITS: `962bffb03dcc4491b1c0ef9c76141c7a`
- SETTINGS: `9733724064cf452ba816404fd71981e1`

## Step 4: Update Configuration

1. Open `cloudflare-backend/wrangler.toml`
2. Replace the KV namespace IDs with the ones you copied:

```toml
[[kv_namespaces]]
binding = "USERS"
id = "YOUR_ACTUAL_USERS_KV_ID"  # Replace this

[[kv_namespaces]]
binding = "VISITS"
id = "YOUR_ACTUAL_VISITS_KV_ID"  # Replace this

[[kv_namespaces]]
binding = "SETTINGS"
id = "YOUR_ACTUAL_SETTINGS_KV_ID"  # Replace this
```

3. Change the JWT secret to something secure:

```toml
[vars]
JWT_SECRET = "your-very-secure-random-string-here"
```

## Step 5: Deploy the Worker API

```bash
cd cloudflare-backend
wrangler deploy
```

This will output your Worker URL, something like:
`https://jail-visit-api.YOUR-SUBDOMAIN.workers.dev` # -- https://jail-visit-api.dlkarpay.workers.dev

Copy this URL - you'll need it for the frontend.

## Step 6: Update Frontend Configuration

1. Open `index-api.html`
2. Find this line near the top:
   ```javascript
   const API_URL = 'https://jail-visit-api.YOUR-SUBDOMAIN.workers.dev'; // UPDATE THIS
   ```
3. Replace it with your actual Worker URL from Step 5

## Step 7: Deploy Frontend to GitHub Pages

Since you already have the frontend on GitHub:

```bash
# Make sure you're in the main project directory
git add .
git commit -m "Add Cloudflare API integration"
git push
```

Your site should update automatically at:
https://davidkarpay.github.io/jail-visit-secure-webbapp/

**Note**: You can also access it at https://jailvisit.karpaylegal.com/ once the DNS fully propagates (may take up to 24 hours).

## Step 8: Test the Deployment

1. Visit your GitHub Pages URL
2. Register a new account (any username/password)
3. Try creating a visit
4. Logout and login again to verify persistence

## Troubleshooting

### CORS Errors
If you see CORS errors in the browser console:
- Make sure the Worker URL in `index-api.html` is correct
- The Worker already includes CORS headers, but verify they're working

### Authentication Errors
- Check that the JWT_SECRET in wrangler.toml was deployed
- Try clearing browser storage and logging in again

### KV Storage Issues
- Verify the KV namespace IDs are correct in wrangler.toml
- Check the Cloudflare dashboard to see if data is being stored

## Security Notes

1. **Change the JWT Secret**: The default secret in wrangler.toml MUST be changed
2. **HTTPS Only**: Both GitHub Pages and Cloudflare Workers use HTTPS by default
3. **Rate Limiting**: Consider adding rate limiting in Cloudflare dashboard
4. **Backup**: KV data can be exported via Wrangler CLI for backup

## Costs

With Cloudflare's free plan:
- 100,000 Worker requests per day
- 1 GB KV storage
- 10,000 KV reads per day
- 1,000 KV writes per day

This should be more than sufficient for your use case.

## Next Steps

1. Consider adding email verification for new users
2. Add password reset functionality
3. Implement data export features
4. Add audit logging for compliance

## Support

If you encounter issues:
1. Check Worker logs in Cloudflare dashboard
2. Use browser developer tools to inspect API calls
3. Verify all configuration values are correct

jail-visit-pending-users -- 01afca8caba04fde817b7b578bf82607
jail-visit-login-pins -- 3349ff23eff24afbab1f7d786ea94b17
jail-visit-reset-codes -- 34fc339022bc4155b11e2d48aeaea13b