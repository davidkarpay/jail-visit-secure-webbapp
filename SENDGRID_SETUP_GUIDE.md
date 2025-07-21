# SendGrid Setup Guide for Email-Only Authentication

## Step 1: Create SendGrid Account

1. Go to https://signup.sendgrid.com/
2. Sign up for a **FREE** account (100 emails/day forever)
3. Verify your email address
4. Complete the account setup

## Step 2: Create API Key

1. Log into SendGrid dashboard
2. Go to **Settings** → **API Keys**
3. Click **Create API Key**
4. Choose **Restricted Access**
5. Give it a name like "Jail Visit Logger"
6. Under **Mail Send**, select **Full Access**
7. Click **Create & View**
8. **COPY THE API KEY** - you won't see it again!

## Step 3: Verify Sender Email (Important!)

SendGrid requires sender verification:

### Option A: Single Sender Verification (Easiest)
1. Go to **Settings** → **Sender Authentication** → **Single Sender Verification**
2. Click **Create New Sender**
3. Fill in your details:
   - From Name: "Jail Visit Logger"
   - From Email: Your email address (like david@karpaylegal.com)
   - Reply To: Same email
   - Company/Address: Your info
4. Click **Create**
5. Check your email and verify the sender

### Option B: Domain Authentication (Advanced)
If you want to use a custom domain like noreply@karpaylegal.com:
1. Go to **Settings** → **Sender Authentication** → **Domain Authentication**
2. Add your domain and follow DNS setup instructions

## Step 4: Update Configuration

Once you have:
- ✅ SendGrid API Key
- ✅ Verified sender email
- ✅ KV namespace IDs (from Cloudflare dashboard)

Update these files:

### 1. Update `wrangler-sendgrid.toml`:
```toml
# Replace with your actual values
SENDGRID_API_KEY = "SG.your-actual-api-key-here"
FROM_EMAIL = "david@karpaylegal.com"  # Must match verified sender

# Replace with your KV namespace IDs
[[kv_namespaces]]
binding = "PENDING_USERS"
id = "your-pending-users-kv-id"

[[kv_namespaces]]
binding = "LOGIN_PINS"
id = "your-login-pins-kv-id"

[[kv_namespaces]]
binding = "RESET_CODES"
id = "your-reset-codes-kv-id"
```

## Step 5: Deploy and Test

```bash
cd cloudflare-backend
wrangler deploy --config wrangler-sendgrid.toml
```

## Testing Checklist

After deployment:

1. **Registration Test**:
   - Visit your app
   - Register with your email
   - Check inbox for verification code
   - Complete verification

2. **PIN Login Test**:
   - Use "Quick PIN" login
   - Check email for PIN
   - Login with PIN

3. **Password Reset Test**:
   - Click "Forgot password"
   - Check email for reset code
   - Reset password successfully

## Important Notes

### Free Tier Limits:
- **100 emails per day** (plenty for personal use)
- After 30 days, you need to add a credit card (but still free up to 100/day)

### Email Deliverability:
- Emails might go to spam initially
- SendGrid has excellent deliverability
- Using your own domain (Option B) improves deliverability

### Security:
- API key is sensitive - never commit it to code
- Stored securely in Cloudflare Workers environment variables
- Emails are sent over HTTPS

## Troubleshooting

### "Forbidden" Error:
- Check API key permissions (needs Mail Send access)
- Verify sender email is authenticated

### Emails Not Arriving:
- Check spam folder
- Verify FROM_EMAIL matches authenticated sender
- Check SendGrid activity log in dashboard

### Worker Deployment Issues:
- Ensure all KV namespace IDs are correct
- Check that API key is properly set
- Review Worker logs in Cloudflare dashboard