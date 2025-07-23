// Enhanced Cloudflare Worker API for JailJogger - Email Only
// Includes Email verification, PIN login, password reset (NO SMS)

// Helper function to generate 6-digit PIN
function generatePIN() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to send email (using SendGrid)
async function sendEmail(to, subject, message, env) {
  if (!env.SENDGRID_API_KEY) {
    console.error('SendGrid API key not configured');
    return false;
  }

  const url = 'https://api.sendgrid.com/v3/mail/send';
  
  const emailData = {
    personalizations: [
      {
        to: [{ email: to }],
        subject: subject
      }
    ],
    from: {
      email: env.FROM_EMAIL || 'noreply@example.com',
      name: 'JailJogger'
    },
    content: [
      {
        type: 'text/plain',
        value: message
      }
    ]
  };

  try {
    console.log('Attempting to send email to:', to);
    console.log('From email:', env.FROM_EMAIL);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.SENDGRID_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(emailData)
    });

    const responseText = await response.text();
    console.log('SendGrid response status:', response.status);
    console.log('SendGrid response:', responseText);

    if (!response.ok) {
      console.error('SendGrid error response:', responseText);
    }

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

// Helper to validate email
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Helper to validate email domain
function isAllowedEmailDomain(email) {
  const allowedDomains = ['@pd15.org', '@pd15.state.fl.us'];
  const emailDomain = email.toLowerCase().substring(email.lastIndexOf('@'));
  return allowedDomains.includes(emailDomain);
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
      // Step 1: Register with email verification
      if (path === '/api/register' && request.method === 'POST') {
        const { username, password, email } = await request.json();
        
        if (!username || !password || !email) {
          return new Response(JSON.stringify({ 
            error: 'Username, password, and email are required' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (!isValidEmail(email)) {
          return new Response(JSON.stringify({ 
            error: 'Please enter a valid email address' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (!isAllowedEmailDomain(email)) {
          return new Response(JSON.stringify({ 
            error: 'Registration is restricted to members of the 15th Judicial Circuit\'s Public Defender Office. Please use your @pd15.org or @pd15.state.fl.us email address.' 
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
          email: email,
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
        const message = `Welcome to JailJogger!

Your verification code is: ${verificationCode}

This code expires in 10 minutes.

If you didn't create this account, please ignore this email.`;

        const sent = await sendEmail(email, 'Verify Your JailJogger Account', message, env);

        if (!sent) {
          return new Response(JSON.stringify({ 
            error: 'Failed to send verification email. Please check your email address and try again.' 
          }), {
            status: 500,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ 
          message: 'Verification code sent to your email. Please check your inbox.',
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
          message: 'Account verified successfully! Welcome to JailJogger.'
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

      // Migration endpoint: Add email to existing user
      if (path === '/api/add-email' && request.method === 'POST') {
        const { username, password, email } = await request.json();
        
        if (!username || !password || !email) {
          return new Response(JSON.stringify({ error: 'Username, password, and email required' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (!isValidEmail(email)) {
          return new Response(JSON.stringify({ 
            error: 'Please enter a valid email address' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (!isAllowedEmailDomain(email)) {
          return new Response(JSON.stringify({ 
            error: 'Registration is restricted to members of the 15th Judicial Circuit\'s Public Defender Office. Please use your @pd15.org or @pd15.state.fl.us email address.' 
          }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // Verify user exists and password is correct
        const userStr = await env.USERS.get(`user:${username}`);
        if (!userStr) {
          return new Response(JSON.stringify({ error: 'User not found' }), {
            status: 404,
            headers: corsHeaders
          });
        }

        const user = JSON.parse(userStr);
        
        // Verify password
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        if (user.passwordHash !== hashHex) {
          return new Response(JSON.stringify({ error: 'Invalid password' }), {
            status: 401,
            headers: corsHeaders
          });
        }

        // Add email to user record
        user.email = email;
        user.isVerified = false; // They'll need to verify the new email
        
        // Save updated user
        await env.USERS.put(`user:${username}`, JSON.stringify(user));

        // Generate verification code
        const verificationCode = generatePIN();
        const expiry = Date.now() + (10 * 60 * 1000); // 10 minutes
        
        await env.PENDING_USERS.put(`verify:${username}`, JSON.stringify({
          code: verificationCode,
          email: email,
          expiry: expiry
        }));

        // Send verification email
        const emailSent = await sendEmail(
          email,
          'Verify Your Email - JailJogger',
          `Your verification code is: ${verificationCode}\n\nThis code expires in 10 minutes.\n\nIf you didn't request this, please ignore this email.`,
          env
        );

        if (!emailSent) {
          return new Response(JSON.stringify({ error: 'Failed to send verification email' }), {
            status: 500,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ 
          message: 'Email added to your account. Please check your email for a verification code.',
          requiresVerification: true
        }), {
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
        const message = `Your JailJogger login PIN is: ${pin}

This PIN expires in 5 minutes.

If you didn't request this, please ignore this email and consider changing your password.`;

        const sent = await sendEmail(user.email, 'Your Login PIN', message, env);

        if (!sent) {
          return new Response(JSON.stringify({ 
            error: 'Failed to send PIN. Please try again.' 
          }), {
            status: 500,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify({ 
          message: 'PIN sent to your email address. Please check your inbox.',
          method: 'email'
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
          message: 'Login successful!'
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
            message: 'If the account exists, a reset code has been sent to the registered email address.' 
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
        const message = `You requested a password reset for your JailJogger account.

Your password reset code is: ${resetCode}

This code expires in 15 minutes.

If you didn't request this reset, please ignore this email and consider securing your account.`;

        await sendEmail(user.email, 'Password Reset Code', message, env);

        return new Response(JSON.stringify({ 
          message: 'If the account exists, a reset code has been sent to the registered email address.' 
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
          message: 'Password reset successfully! You can now log in with your new password.' 
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
        try {
          console.log('Save visit request received for user:', userId);
          const visit = await request.json();
          console.log('Visit data:', JSON.stringify(visit));
          
          visit.id = crypto.randomUUID();
          visit.userId = userId;
          visit.createdAt = new Date().toISOString();
          
          // Get existing visits
          const visitsStr = await env.VISITS.get(`visits:${userId}`, 'json');
          const visits = visitsStr || [];
          console.log('Existing visits count:', visits.length);
          
          // Add new visit
          visits.unshift(visit);
          
          // Save back to KV
          await env.VISITS.put(`visits:${userId}`, JSON.stringify(visits));
          console.log('Visit saved successfully');
          
          return new Response(JSON.stringify(visit), {
            headers: corsHeaders
          });
        } catch (error) {
          console.error('Error saving visit:', error);
          return new Response(JSON.stringify({ error: 'Failed to save visit' }), {
            status: 500,
            headers: corsHeaders
          });
        }
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