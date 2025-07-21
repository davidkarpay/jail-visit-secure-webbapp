// Enhanced Cloudflare Worker API for Jail Visit Logger
// Includes SMS/Email verification, PIN login, password reset

// Helper function to generate 6-digit PIN
function generatePIN() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to send SMS (using Twilio)
async function sendSMS(phoneNumber, message, env) {
  if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN) {
    console.error('Twilio credentials not configured');
    return false;
  }

  const url = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  
  const body = new URLSearchParams({
    To: phoneNumber,
    From: env.TWILIO_PHONE_NUMBER,
    Body: message
  });

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body
    });

    return response.ok;
  } catch (error) {
    console.error('SMS send error:', error);
    return false;
  }
}

// Helper function to send email (using Mailgun)
async function sendEmail(to, subject, message, env) {
  if (!env.MAILGUN_API_KEY || !env.MAILGUN_DOMAIN) {
    console.error('Mailgun credentials not configured');
    return false;
  }

  const url = `https://api.mailgun.net/v3/${env.MAILGUN_DOMAIN}/messages`;
  
  const formData = new FormData();
  formData.append('from', `Jail Visit Logger <noreply@${env.MAILGUN_DOMAIN}>`);
  formData.append('to', to);
  formData.append('subject', subject);
  formData.append('text', message);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + btoa(`api:${env.MAILGUN_API_KEY}`)
      },
      body: formData
    });

    return response.ok;
  } catch (error) {
    console.error('Email send error:', error);
    return false;
  }
}

// Helper function to generate JWT
async function generateJWT(userId, secret) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const payload = {
    sub: userId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
  };
  
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${encodedHeader}.${encodedPayload}`)
  );
  
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

// Helper function to verify JWT
async function verifyJWT(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const encoder = new TextEncoder();
    
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureBuffer = Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    
    const verified = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      encoder.encode(`${header}.${payload}`)
    );
    
    if (!verified) return null;
    
    const decodedPayload = JSON.parse(atob(payload));
    
    // Check expiration
    if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    
    return decodedPayload;
  } catch (e) {
    return null;
  }
}

// Helper to hash passwords
async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

// Helper to format phone number
function formatPhoneNumber(phone) {
  // Remove all non-digits
  const digits = phone.replace(/\D/g, '');
  
  // Add +1 if it's a 10-digit US number
  if (digits.length === 10) {
    return `+1${digits}`;
  } else if (digits.length === 11 && digits.startsWith('1')) {
    return `+${digits}`;
  }
  
  return phone; // Return as-is if we can't format it
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Step 1: Register with phone/email verification
      if (path === '/api/register' && request.method === 'POST') {
        const { username, password, email, phone } = await request.json();
        
        if (!username || !password || (!email && !phone)) {
          return new Response(JSON.stringify({ 
            error: 'Username, password, and either email or phone required' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // Check if user exists
        const existingUser = await env.USERS.get(`user:${username}`);
        if (existingUser) {
          return new Response(JSON.stringify({ error: 'User already exists' }), {
            status: 409,
            headers: corsHeaders
          });
        }

        // Generate verification code
        const verificationCode = generatePIN();
        const codeExpiry = Date.now() + (10 * 60 * 1000); // 10 minutes

        // Create pending user
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const saltStr = btoa(String.fromCharCode(...salt));
        const hashedPassword = await hashPassword(password, saltStr);
        
        const pendingUser = {
          id: crypto.randomUUID(),
          username,
          password: hashedPassword,
          salt: saltStr,
          email: email || null,
          phone: phone ? formatPhoneNumber(phone) : null,
          verified: false,
          verificationCode,
          codeExpiry,
          createdAt: new Date().toISOString()
        };

        // Store pending user temporarily
        await env.PENDING_USERS.put(`pending:${username}`, JSON.stringify(pendingUser), {
          expirationTtl: 900 // 15 minutes
        });

        // Send verification code
        let sent = false;
        if (phone) {
          const message = `Your Jail Visit Logger verification code is: ${verificationCode}. This code expires in 10 minutes.`;
          sent = await sendSMS(formatPhoneNumber(phone), message, env);
        } else if (email) {
          const message = `Your Jail Visit Logger verification code is: ${verificationCode}\n\nThis code expires in 10 minutes.\n\nIf you didn't request this, please ignore this email.`;
          sent = await sendEmail(email, 'Verify Your Account', message, env);
        }

        if (!sent) {
          return new Response(JSON.stringify({ 
            error: 'Failed to send verification code. Please try again.' 
          }), {
            status: 500,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ 
          message: 'Verification code sent. Please check your ' + (phone ? 'phone' : 'email'),
          requiresVerification: true,
          username
        }), {
          headers: corsHeaders
        });
      }

      // Step 2: Verify registration code
      if (path === '/api/verify-registration' && request.method === 'POST') {
        const { username, code } = await request.json();
        
        const pendingUserStr = await env.PENDING_USERS.get(`pending:${username}`);
        if (!pendingUserStr) {
          return new Response(JSON.stringify({ 
            error: 'Verification expired or invalid username' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const pendingUser = JSON.parse(pendingUserStr);
        
        if (pendingUser.verificationCode !== code) {
          return new Response(JSON.stringify({ error: 'Invalid verification code' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (Date.now() > pendingUser.codeExpiry) {
          await env.PENDING_USERS.delete(`pending:${username}`);
          return new Response(JSON.stringify({ error: 'Verification code expired' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // Create verified user
        pendingUser.verified = true;
        delete pendingUser.verificationCode;
        delete pendingUser.codeExpiry;
        
        await env.USERS.put(`user:${username}`, JSON.stringify(pendingUser));
        await env.PENDING_USERS.delete(`pending:${username}`);
        
        // Generate token
        const token = await generateJWT(pendingUser.id, env.JWT_SECRET || 'your-secret-key');
        
        return new Response(JSON.stringify({ 
          token, 
          userId: pendingUser.id,
          message: 'Account verified successfully'
        }), {
          headers: corsHeaders
        });
      }

      // Login (traditional)
      if (path === '/api/login' && request.method === 'POST') {
        const { username, password } = await request.json();
        
        const userStr = await env.USERS.get(`user:${username}`);
        if (!userStr) {
          return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
            status: 401,
            headers: corsHeaders
          });
        }

        const user = JSON.parse(userStr);
        
        if (!user.verified) {
          return new Response(JSON.stringify({ 
            error: 'Account not verified. Please complete verification first.' 
          }), {
            status: 401,
            headers: corsHeaders
          });
        }

        const hashedPassword = await hashPassword(password, user.salt);
        
        if (hashedPassword !== user.password) {
          return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
            status: 401,
            headers: corsHeaders
          });
        }

        const token = await generateJWT(user.id, env.JWT_SECRET || 'your-secret-key');
        
        return new Response(JSON.stringify({ token, userId: user.id }), {
          headers: corsHeaders
        });
      }

      // Request PIN login
      if (path === '/api/request-pin' && request.method === 'POST') {
        const { username } = await request.json();
        
        const userStr = await env.USERS.get(`user:${username}`);
        if (!userStr) {
          return new Response(JSON.stringify({ error: 'User not found' }), {
            status: 404,
            headers: corsHeaders
          });
        }

        const user = JSON.parse(userStr);
        
        if (!user.verified) {
          return new Response(JSON.stringify({ 
            error: 'Account not verified' 
          }), {
            status: 401,
            headers: corsHeaders
          });
        }

        // Generate PIN
        const pin = generatePIN();
        const pinExpiry = Date.now() + (5 * 60 * 1000); // 5 minutes

        // Store PIN temporarily
        await env.LOGIN_PINS.put(`pin:${username}`, JSON.stringify({
          pin,
          expiry: pinExpiry,
          userId: user.id
        }), {
          expirationTtl: 300 // 5 minutes
        });

        // Send PIN
        let sent = false;
        if (user.phone) {
          const message = `Your Jail Visit Logger login PIN is: ${pin}. This PIN expires in 5 minutes.`;
          sent = await sendSMS(user.phone, message, env);
        } else if (user.email) {
          const message = `Your Jail Visit Logger login PIN is: ${pin}\n\nThis PIN expires in 5 minutes.\n\nIf you didn't request this, please ignore this email.`;
          sent = await sendEmail(user.email, 'Login PIN', message, env);
        }

        if (!sent) {
          return new Response(JSON.stringify({ 
            error: 'Failed to send PIN. Please try again.' 
          }), {
            status: 500,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ 
          message: 'PIN sent to your ' + (user.phone ? 'phone' : 'email'),
          method: user.phone ? 'sms' : 'email'
        }), {
          headers: corsHeaders
        });
      }

      // Verify PIN login
      if (path === '/api/verify-pin' && request.method === 'POST') {
        const { username, pin } = await request.json();
        
        const pinDataStr = await env.LOGIN_PINS.get(`pin:${username}`);
        if (!pinDataStr) {
          return new Response(JSON.stringify({ 
            error: 'PIN expired or not found' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const pinData = JSON.parse(pinDataStr);
        
        if (pinData.pin !== pin) {
          return new Response(JSON.stringify({ error: 'Invalid PIN' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (Date.now() > pinData.expiry) {
          await env.LOGIN_PINS.delete(`pin:${username}`);
          return new Response(JSON.stringify({ error: 'PIN expired' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // Clean up PIN
        await env.LOGIN_PINS.delete(`pin:${username}`);
        
        // Generate token
        const token = await generateJWT(pinData.userId, env.JWT_SECRET || 'your-secret-key');
        
        return new Response(JSON.stringify({ 
          token, 
          userId: pinData.userId,
          message: 'Login successful'
        }), {
          headers: corsHeaders
        });
      }

      // Request password reset
      if (path === '/api/reset-password' && request.method === 'POST') {
        const { username } = await request.json();
        
        const userStr = await env.USERS.get(`user:${username}`);
        if (!userStr) {
          // Don't reveal if user exists or not
          return new Response(JSON.stringify({ 
            message: 'If the account exists, a reset code has been sent.' 
          }), {
            headers: corsHeaders
          });
        }

        const user = JSON.parse(userStr);
        
        // Generate reset code
        const resetCode = generatePIN();
        const resetExpiry = Date.now() + (15 * 60 * 1000); // 15 minutes

        // Store reset code
        await env.RESET_CODES.put(`reset:${username}`, JSON.stringify({
          code: resetCode,
          expiry: resetExpiry,
          userId: user.id
        }), {
          expirationTtl: 900 // 15 minutes
        });

        // Send reset code
        let sent = false;
        if (user.phone) {
          const message = `Your Jail Visit Logger password reset code is: ${resetCode}. This code expires in 15 minutes.`;
          sent = await sendSMS(user.phone, message, env);
        } else if (user.email) {
          const message = `Your Jail Visit Logger password reset code is: ${resetCode}\n\nThis code expires in 15 minutes.\n\nIf you didn't request this, please ignore this email.`;
          sent = await sendEmail(user.email, 'Password Reset', message, env);
        }

        return new Response(JSON.stringify({ 
          message: 'If the account exists, a reset code has been sent.' 
        }), {
          headers: corsHeaders
        });
      }

      // Verify reset code and change password
      if (path === '/api/confirm-reset' && request.method === 'POST') {
        const { username, code, newPassword } = await request.json();
        
        if (!newPassword || newPassword.length < 6) {
          return new Response(JSON.stringify({ 
            error: 'Password must be at least 6 characters' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const resetDataStr = await env.RESET_CODES.get(`reset:${username}`);
        if (!resetDataStr) {
          return new Response(JSON.stringify({ 
            error: 'Reset code expired or not found' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const resetData = JSON.parse(resetDataStr);
        
        if (resetData.code !== code) {
          return new Response(JSON.stringify({ error: 'Invalid reset code' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (Date.now() > resetData.expiry) {
          await env.RESET_CODES.delete(`reset:${username}`);
          return new Response(JSON.stringify({ error: 'Reset code expired' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // Update password
        const userStr = await env.USERS.get(`user:${username}`);
        const user = JSON.parse(userStr);
        
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const saltStr = btoa(String.fromCharCode(...salt));
        const hashedPassword = await hashPassword(newPassword, saltStr);
        
        user.password = hashedPassword;
        user.salt = saltStr;
        
        await env.USERS.put(`user:${username}`, JSON.stringify(user));
        await env.RESET_CODES.delete(`reset:${username}`);
        
        return new Response(JSON.stringify({ 
          message: 'Password reset successfully. You can now log in with your new password.' 
        }), {
          headers: corsHeaders
        });
      }

      // All other routes require authentication
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: corsHeaders
        });
      }

      const token = authHeader.substring(7);
      const payload = await verifyJWT(token, env.JWT_SECRET || 'your-secret-key');
      
      if (!payload) {
        return new Response(JSON.stringify({ error: 'Invalid token' }), {
          status: 401,
          headers: corsHeaders
        });
      }

      const userId = payload.sub;

      // Get visits
      if (path === '/api/visits' && request.method === 'GET') {
        const visitsStr = await env.VISITS.get(`visits:${userId}`, 'json');
        const visits = visitsStr || [];
        
        return new Response(JSON.stringify(visits), {
          headers: corsHeaders
        });
      }

      // Create visit
      if (path === '/api/visits' && request.method === 'POST') {
        const visit = await request.json();
        visit.id = crypto.randomUUID();
        visit.userId = userId;
        visit.createdAt = new Date().toISOString();
        
        // Get existing visits
        const visitsStr = await env.VISITS.get(`visits:${userId}`, 'json');
        const visits = visitsStr || [];
        
        // Add new visit
        visits.unshift(visit);
        
        // Save back to KV
        await env.VISITS.put(`visits:${userId}`, JSON.stringify(visits));
        
        return new Response(JSON.stringify(visit), {
          headers: corsHeaders
        });
      }

      // Update visit
      if (path.startsWith('/api/visits/') && request.method === 'PUT') {
        const visitId = path.split('/')[3];
        const updates = await request.json();
        
        // Get existing visits
        const visitsStr = await env.VISITS.get(`visits:${userId}`, 'json');
        const visits = visitsStr || [];
        
        // Find and update visit
        const index = visits.findIndex(v => v.id === visitId);
        if (index === -1) {
          return new Response(JSON.stringify({ error: 'Visit not found' }), {
            status: 404,
            headers: corsHeaders
          });
        }
        
        visits[index] = { ...visits[index], ...updates, id: visitId, userId };
        
        // Save back to KV
        await env.VISITS.put(`visits:${userId}`, JSON.stringify(visits));
        
        return new Response(JSON.stringify(visits[index]), {
          headers: corsHeaders
        });
      }

      // Delete visit
      if (path.startsWith('/api/visits/') && request.method === 'DELETE') {
        const visitId = path.split('/')[3];
        
        // Get existing visits
        const visitsStr = await env.VISITS.get(`visits:${userId}`, 'json');
        const visits = visitsStr || [];
        
        // Filter out the visit
        const filteredVisits = visits.filter(v => v.id !== visitId);
        
        if (filteredVisits.length === visits.length) {
          return new Response(JSON.stringify({ error: 'Visit not found' }), {
            status: 404,
            headers: corsHeaders
          });
        }
        
        // Save back to KV
        await env.VISITS.put(`visits:${userId}`, JSON.stringify(filteredVisits));
        
        return new Response(JSON.stringify({ success: true }), {
          headers: corsHeaders
        });
      }

      // Get user settings
      if (path === '/api/settings' && request.method === 'GET') {
        const settingsStr = await env.SETTINGS.get(`settings:${userId}`);
        const settings = settingsStr ? JSON.parse(settingsStr) : {};
        
        return new Response(JSON.stringify(settings), {
          headers: corsHeaders
        });
      }

      // Update user settings
      if (path === '/api/settings' && request.method === 'PUT') {
        const settings = await request.json();
        await env.SETTINGS.put(`settings:${userId}`, JSON.stringify(settings));
        
        return new Response(JSON.stringify(settings), {
          headers: corsHeaders
        });
      }

      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: corsHeaders
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: corsHeaders
      });
    }
  }
};