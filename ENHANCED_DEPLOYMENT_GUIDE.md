# Enhanced Authentication Deployment Guide

This guide covers deploying the enhanced version with SMS/Email verification, PIN login, and password reset features.

## Prerequisites

- Cloudflare account (free plan)
- Twilio account (for SMS) - **Optional but recommended**
- Mailgun account (for email) - **Optional but recommended**

## Step 1: Set Up External Services

### Option A: Twilio (for SMS)

1. Go to https://console.twilio.com/
2. Sign up for a free account ($15 trial credit)
3. Get a phone number from Twilio Console
4. Note down:
   - Account SID
   - Auth Token
   - Your Twilio phone number

### Option B: Mailgun (for Email)

1. Go to https://app.mailgun.com/
2. Sign up for free account
3. Add and verify a domain (or use sandbox domain for testing)
4. Note down:
   - API Key
   - Domain name

## Step 2: Create Additional KV Namespaces

You need 3 more KV namespaces for the enhanced features:

### Using Cloudflare Dashboard:

1. Go to Cloudflare Dashboard → Workers & Pages → KV
2. Create these namespaces:
   - `jail-visit-pending-users` (for registration verification)
   - `jail-visit-login-pins` (for PIN login)
   - `jail-visit-reset-codes` (for password reset)
3. Copy the IDs

### Using Wrangler CLI:

```bash
cd cloudflare-backend
wrangler kv:namespace create "PENDING_USERS"
wrangler kv:namespace create "LOGIN_PINS"
wrangler kv:namespace create "RESET_CODES"
```

## Step 3: Update Enhanced Configuration

1. Open `cloudflare-backend/wrangler-enhanced.toml`
2. Update with your KV namespace IDs:

```toml
name = "jail-visit-api-enhanced"
main = "worker-enhanced.js"
compatibility_date = "2024-01-01"

# Existing KV Namespaces
[[kv_namespaces]]
binding = "USERS"
id = "cf359fa838de461b90d015512bc67051"

[[kv_namespaces]]
binding = "VISITS"
id = "962bffb03dcc4491b1c0ef9c76141c7a"

[[kv_namespaces]]
binding = "SETTINGS"
id = "9733724064cf452ba816404fd71981e1"

# New KV namespaces - UPDATE THESE
[[kv_namespaces]]
binding = "PENDING_USERS"
id = "YOUR_PENDING_USERS_KV_ID"

[[kv_namespaces]]
binding = "LOGIN_PINS"
id = "YOUR_LOGIN_PINS_KV_ID"

[[kv_namespaces]]
binding = "RESET_CODES"
id = "YOUR_RESET_CODES_KV_ID"

# Environment variables
[vars]
JWT_SECRET = "karpay-jail-visit-secure-jwt-2024-production-key-7x9z"

# Twilio Configuration (UPDATE THESE)
TWILIO_ACCOUNT_SID = "YOUR_TWILIO_ACCOUNT_SID"
TWILIO_AUTH_TOKEN = "YOUR_TWILIO_AUTH_TOKEN"
TWILIO_PHONE_NUMBER = "YOUR_TWILIO_PHONE_NUMBER"

# Mailgun Configuration (UPDATE THESE)
MAILGUN_API_KEY = "YOUR_MAILGUN_API_KEY"
MAILGUN_DOMAIN = "YOUR_MAILGUN_DOMAIN"
```

## Step 4: Deploy Enhanced Worker

```bash
cd cloudflare-backend
wrangler deploy --config wrangler-enhanced.toml
```

This will give you a new Worker URL like:
`https://jail-visit-api-enhanced.YOUR-SUBDOMAIN.workers.dev`

## Step 5: Update Enhanced Frontend

1. Open `index-enhanced.html`
2. Update the API URL:

```javascript
const API_URL = 'https://jail-visit-api-enhanced.YOUR-SUBDOMAIN.workers.dev';
```

## Step 6: Test the Enhanced Features

### Registration with Verification:
1. Register with email or phone number
2. Check for verification code
3. Enter code to complete registration

### PIN Login:
1. Click "Quick PIN" tab
2. Enter username
3. Check phone/email for PIN
4. Enter PIN to log in

### Password Reset:
1. Click "Forgot password?"
2. Enter username
3. Check phone/email for reset code
4. Enter code and new password

## Configuration Options

### SMS Only (Recommended for Security)
```toml
# Include only Twilio settings
TWILIO_ACCOUNT_SID = "your_sid"
TWILIO_AUTH_TOKEN = "your_token"
TWILIO_PHONE_NUMBER = "+1234567890"

# Leave Mailgun blank
MAILGUN_API_KEY = ""
MAILGUN_DOMAIN = ""
```

### Email Only
```toml
# Leave Twilio blank
TWILIO_ACCOUNT_SID = ""
TWILIO_AUTH_TOKEN = ""
TWILIO_PHONE_NUMBER = ""

# Include only Mailgun settings
MAILGUN_API_KEY = "your_key"
MAILGUN_DOMAIN = "your_domain"
```

### Both SMS and Email
Include all settings - users can register with either phone or email.

## Security Features

### Enhanced Security:
- ✅ Phone/Email verification required for new accounts
- ✅ One-time PIN login (no password needed after setup)
- ✅ Secure password reset via SMS/email
- ✅ Time-limited verification codes (5-15 minutes)
- ✅ Automatic cleanup of expired codes
- ✅ Rate limiting built into external services

### New User Flow:
1. **Register** → Enter username, password, phone/email
2. **Verify** → Receive and enter 6-digit code
3. **Login** → Use username/password OR request PIN
4. **PIN Login** → Receive 6-digit PIN, enter to log in

## Costs

### Cloudflare (Free Tier):
- Same as before + 3 additional KV namespaces (still within limits)

### Twilio (SMS):
- $0.0075 per SMS (very cheap)
- Free trial includes $15 credit
- Typical usage: <$5/month for personal use

### Mailgun (Email):
- First 5,000 emails free per month
- $0.80 per 1,000 emails after that
- Typical usage: Free for personal use

## Troubleshooting

### SMS Not Sending:
- Verify Twilio credentials
- Check phone number format (+1234567890)
- Ensure sufficient Twilio balance

### Email Not Sending:
- Verify Mailgun domain
- Check spam folder
- Verify Mailgun API key

### Verification Codes:
- Codes expire in 5-15 minutes
- Check Worker logs in Cloudflare dashboard
- Ensure KV namespace IDs are correct

## Migration from Basic Version

Users from the basic version will need to:
1. Re-register their accounts (old local data incompatible)
2. Provide phone/email for verification
3. Data will be migrated to the new secure cloud storage

## Recommended Setup

For maximum security and convenience:
1. **Use SMS verification** (more secure than email)
2. **Enable PIN login** for daily use
3. **Set up both SMS and email** as backup options
4. **Use strong JWT secret** in production

The enhanced version provides enterprise-level security while maintaining ease of use for daily jail visit logging.