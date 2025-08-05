// Enhanced Cloudflare Worker API for JailJogger
// Includes Email verification, PIN login, password reset using EmailJS API
// This approach is simpler and doesn't require complex Gmail API setup

// Helper function to generate 6-digit PIN
function generatePIN() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to send email using EmailJS API
async function sendEmail(to, subject, message, env, emailType = 'default') {
  if (!env.EMAILJS_SERVICE_ID || !env.EMAILJS_USER_ID) {
    console.error('EmailJS credentials not configured');
    return false;
  }

  // Use different templates for different email types
  let templateId = env.EMAILJS_TEMPLATE_ID; // Default template
  if (emailType === 'reset' && env.EMAILJS_RESET_TEMPLATE_ID) {
    templateId = env.EMAILJS_RESET_TEMPLATE_ID;
  } else if (emailType === 'pin' && env.EMAILJS_PIN_TEMPLATE_ID) {
    templateId = env.EMAILJS_PIN_TEMPLATE_ID;
  } else if (emailType === 'verify' && env.EMAILJS_VERIFY_TEMPLATE_ID) {
    templateId = env.EMAILJS_VERIFY_TEMPLATE_ID;
  }

  try {
    const response = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        service_id: env.EMAILJS_SERVICE_ID,
        template_id: templateId,
        user_id: env.EMAILJS_USER_ID,
        accessToken: env.EMAILJS_USER_ID, // Some versions need this
        template_params: {
          to_email: to,
          to_name: to.split('@')[0], // Extract name from email
          subject: subject,
          message: message,
          from_name: 'JailJogger',
          reply_to: 'noreply@jailjogger.com'
        }
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('EmailJS error:', response.status, errorText);
    }
    return response.ok;
  } catch (error) {
    console.error('Email send error:', error);
    return false;
  }
}

// Email templates
function getVerificationEmailMessage(code, username) {
  return `Hello ${username},

Welcome to JailJogger! 

To complete your account setup, please enter this verification code in the app:

VERIFICATION CODE: ${code}

This code will expire in 15 minutes.

If you didn't request this verification, please ignore this email.

---
JailJogger
15th Judicial Circuit Public Defender Office`;
}

function getPINEmailMessage(pin, username) {
  return `Hello ${username},

Here's your one-time login PIN for JailJogger:

LOGIN PIN: ${pin}

This PIN will expire in 10 minutes.

If you didn't request this login, please ignore this email.

---
JailJogger
15th Judicial Circuit Public Defender Office`;
}

function getPasswordResetEmailMessage(code, username) {
  return `Hello ${username},

You requested a password reset for your JailJogger account.

Use this code to set a new password:

RESET CODE: ${code}

This code will expire in 15 minutes.

If you didn't request this reset, please ignore this email.

---
JailJogger
15th Judicial Circuit Public Defender Office`;
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
    
    const signatureBytes = new Uint8Array(
      atob(signature.replace(/-/g, '+').replace(/_/g, '/'))
        .split('').map(c => c.charCodeAt(0))
    );
    
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBytes,
      encoder.encode(`${header}.${payload}`)
    );
    
    if (isValid) {
      const payloadData = JSON.parse(atob(payload));
      return { valid: true, payload: payloadData };
    }
    
    return { valid: false };
  } catch (error) {
    return { valid: false };
  }
}

// Original API password hashing (base64 with salt)
async function hashPasswordOriginal(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

// New API password hashing (array with username as salt)
async function hashPasswordNew(password, username) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + username);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer));
}

// Compare password function - handles both old and new formats
async function comparePassword(password, username, user) {
  // Check if this is an old format user (has salt property and password is string)
  if (user.salt && typeof user.password === 'string') {
    const originalHash = await hashPasswordOriginal(password, user.salt);
    return originalHash === user.password;
  }
  
  // New format (password is array)
  if (Array.isArray(user.password)) {
    const newHash = await hashPasswordNew(password, username);
    if (newHash.length !== user.password.length) return false;
    
    for (let i = 0; i < newHash.length; i++) {
      if (newHash[i] !== user.password[i]) return false;
    }
    return true;
  }
  
  return false;
}

// Main request handler
export default {
  async fetch(request, env, ctx) {
    // Enable CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    try {
      // Registration endpoint
      if (url.pathname === '/api/register' && request.method === 'POST') {
        const { username, password, email } = await request.json();
        
        // Validate email domain
        const allowedDomains = ['@pd15.org', '@pd15.state.fl.us'];
        const emailDomain = email.toLowerCase().substring(email.lastIndexOf('@'));
        
        if (!allowedDomains.includes(emailDomain)) {
          return new Response(JSON.stringify({
            error: 'Registration restricted to 15th Judicial Circuit Public Defender Office members'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Check if user already exists (check both new and old key formats)
        const existingUser = await env.USERS.get(username) || await env.USERS.get(`user:${username}`);
        if (existingUser) {
          return new Response(JSON.stringify({
            error: 'Username already exists'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Generate verification code
        const verificationCode = generatePIN();
        
        // Store pending user (expires in 15 minutes)
        const hashedPassword = await hashPasswordNew(password, username);
        const pendingUser = {
          username,
          password: hashedPassword,
          email,
          verificationCode,
          createdAt: Date.now()
        };
        
        await env.PENDING_USERS.put(username, JSON.stringify(pendingUser), { expirationTtl: 900 });
        
        // Send verification email
        const emailSent = await sendEmail(
          email,
          'JailJogger - Verify Your Account',
          getVerificationEmailMessage(verificationCode, username),
          env,
          'verify'
        );
        
        if (!emailSent) {
          return new Response(JSON.stringify({
            error: 'Failed to send verification email. Please try again.'
          }), { 
            status: 500, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        return new Response(JSON.stringify({
          message: 'Registration successful! Please check your email for verification code.'
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Verification endpoint
      if (url.pathname === '/api/verify-registration' && request.method === 'POST') {
        const { username, code } = await request.json();
        
        const pendingUserData = await env.PENDING_USERS.get(username);
        if (!pendingUserData) {
          return new Response(JSON.stringify({
            error: 'Verification code expired or invalid'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const pendingUser = JSON.parse(pendingUserData);
        
        if (pendingUser.verificationCode !== code) {
          return new Response(JSON.stringify({
            error: 'Invalid verification code'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Create verified user
        const userId = crypto.randomUUID();
        const user = {
          id: userId,
          username: pendingUser.username,
          password: pendingUser.password,
          email: pendingUser.email,
          verified: true,
          createdAt: Date.now()
        };

        await env.USERS.put(pendingUser.username, JSON.stringify(user));
        await env.PENDING_USERS.delete(username);

        // Generate JWT token
        const token = await generateJWT(userId, env.JWT_SECRET);

        return new Response(JSON.stringify({
          message: 'Account verified successfully!',
          token,
          userId
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Login endpoint
      if (url.pathname === '/api/login' && request.method === 'POST') {
        const { username, password } = await request.json();
        
        const userData = await env.USERS.get(username) || await env.USERS.get(`user:${username}`);
        if (!userData) {
          return new Response(JSON.stringify({
            error: 'Invalid username or password'
          }), { 
            status: 401, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const user = JSON.parse(userData);
        const isValidPassword = await comparePassword(password, username, user);

        if (!isValidPassword) {
          return new Response(JSON.stringify({
            error: 'Invalid username or password'
          }), { 
            status: 401, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const token = await generateJWT(user.id, env.JWT_SECRET);

        return new Response(JSON.stringify({
          message: 'Login successful',
          token,
          userId: user.id
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Request PIN endpoint
      if (url.pathname === '/api/request-pin' && request.method === 'POST') {
        const { username } = await request.json();
        
        const userData = await env.USERS.get(username) || await env.USERS.get(`user:${username}`);
        if (!userData) {
          return new Response(JSON.stringify({
            error: 'User not found'
          }), { 
            status: 404, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const user = JSON.parse(userData);
        if (!user.email) {
          return new Response(JSON.stringify({
            error: 'No email address on file. Please use password login.'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const pin = generatePIN();
        
        // Store PIN (expires in 10 minutes)
        await env.LOGIN_PINS.put(username, JSON.stringify({
          pin,
          userId: user.id,
          createdAt: Date.now()
        }), { expirationTtl: 600 });

        // Send PIN email
        const emailSent = await sendEmail(
          user.email,
          'JailJogger - Your Login PIN',
          getPINEmailMessage(pin, username),
          env,
          'pin'
        );

        if (!emailSent) {
          return new Response(JSON.stringify({
            error: 'Failed to send PIN email. Please try again.'
          }), { 
            status: 500, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        return new Response(JSON.stringify({
          message: 'PIN sent to your email address'
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Verify PIN endpoint
      if (url.pathname === '/api/verify-pin' && request.method === 'POST') {
        const { username, pin } = await request.json();
        
        const pinData = await env.LOGIN_PINS.get(username);
        if (!pinData) {
          return new Response(JSON.stringify({
            error: 'PIN expired or invalid'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const storedPin = JSON.parse(pinData);
        
        if (storedPin.pin !== pin) {
          return new Response(JSON.stringify({
            error: 'Invalid PIN'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Delete used PIN
        await env.LOGIN_PINS.delete(username);

        const token = await generateJWT(storedPin.userId, env.JWT_SECRET);

        return new Response(JSON.stringify({
          message: 'PIN verified successfully!',
          token,
          userId: storedPin.userId
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Password reset request endpoint
      if (url.pathname === '/api/reset-password' && request.method === 'POST') {
        const { username } = await request.json();
        
        const userData = await env.USERS.get(username) || await env.USERS.get(`user:${username}`);
        if (!userData) {
          // Don't reveal if user exists for security
          return new Response(JSON.stringify({
            message: 'If the username exists, a reset code has been sent'
          }), { 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const user = JSON.parse(userData);
        if (!user.email) {
          return new Response(JSON.stringify({
            message: 'If the username exists, a reset code has been sent'
          }), { 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const resetCode = generatePIN();
        
        // Store reset code (expires in 15 minutes)
        await env.RESET_CODES.put(username, JSON.stringify({
          code: resetCode,
          userId: user.id,
          createdAt: Date.now()
        }), { expirationTtl: 900 });

        // Send reset email
        await sendEmail(
          user.email,
          'JailJogger - Password Reset Code',
          getPasswordResetEmailMessage(resetCode, username),
          env,
          'reset'
        );

        return new Response(JSON.stringify({
          message: 'If the username exists, a reset code has been sent'
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Confirm password reset endpoint
      if (url.pathname === '/api/confirm-reset' && request.method === 'POST') {
        const { username, code, newPassword } = await request.json();
        
        const resetData = await env.RESET_CODES.get(username);
        if (!resetData) {
          return new Response(JSON.stringify({
            error: 'Reset code expired or invalid'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const storedReset = JSON.parse(resetData);
        
        if (storedReset.code !== code) {
          return new Response(JSON.stringify({
            error: 'Invalid reset code'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Update user password
        const userData = await env.USERS.get(username) || await env.USERS.get(`user:${username}`);
        const user = JSON.parse(userData);
        user.password = await hashPasswordNew(newPassword, username);
        // Remove salt if it exists (converting from old to new format)
        delete user.salt;
        
        await env.USERS.put(username, JSON.stringify(user));
        await env.RESET_CODES.delete(username);

        return new Response(JSON.stringify({
          message: 'Password reset successful!'
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Add email to existing account endpoint
      if (url.pathname === '/api/add-email' && request.method === 'POST') {
        const { username, password, email } = await request.json();
        
        // Validate email domain
        const allowedDomains = ['@pd15.org', '@pd15.state.fl.us'];
        const emailDomain = email.toLowerCase().substring(email.lastIndexOf('@'));
        
        if (!allowedDomains.includes(emailDomain)) {
          return new Response(JSON.stringify({
            error: 'Email must be from 15th Judicial Circuit Public Defender Office'
          }), { 
            status: 400, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const userData = await env.USERS.get(username) || await env.USERS.get(`user:${username}`);
        if (!userData) {
          return new Response(JSON.stringify({
            error: 'User not found'
          }), { 
            status: 404, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const user = JSON.parse(userData);
        const isValidPassword = await comparePassword(password, username, user);

        if (!isValidPassword) {
          return new Response(JSON.stringify({
            error: 'Invalid password'
          }), { 
            status: 401, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        // Update user with email
        user.email = email;
        await env.USERS.put(username, JSON.stringify(user));

        return new Response(JSON.stringify({
          message: 'Email added successfully! You can now use PIN login and password reset.'
        }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Protected endpoints - require authentication
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({
          error: 'Unauthorized'
        }), { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      const token = authHeader.split(' ')[1];
      const jwtResult = await verifyJWT(token, env.JWT_SECRET);
      
      if (!jwtResult.valid) {
        return new Response(JSON.stringify({
          error: 'Invalid token'
        }), { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      const userId = jwtResult.payload.sub;

      // Get visits
      if (url.pathname === '/api/visits' && request.method === 'GET') {
        const visitsData = await env.VISITS.get(`user:${userId}`);
        const visits = visitsData ? JSON.parse(visitsData) : [];
        
        return new Response(JSON.stringify(visits), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Add visit
      if (url.pathname === '/api/visits' && request.method === 'POST') {
        const visitData = await request.json();
        
        const visit = {
          id: crypto.randomUUID(),
          ...visitData,
          createdAt: new Date().toISOString()
        };

        const existingVisitsData = await env.VISITS.get(`user:${userId}`);
        const visits = existingVisitsData ? JSON.parse(existingVisitsData) : [];
        
        visits.unshift(visit);
        await env.VISITS.put(`user:${userId}`, JSON.stringify(visits));

        return new Response(JSON.stringify(visit), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Update visit
      if (url.pathname.startsWith('/api/visits/') && request.method === 'PUT') {
        const visitId = url.pathname.split('/')[3];
        const updateData = await request.json();
        
        const existingVisitsData = await env.VISITS.get(`user:${userId}`);
        const visits = existingVisitsData ? JSON.parse(existingVisitsData) : [];
        
        const visitIndex = visits.findIndex(v => v.id === visitId);
        if (visitIndex === -1) {
          return new Response(JSON.stringify({
            error: 'Visit not found'
          }), { 
            status: 404, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        visits[visitIndex] = { ...visits[visitIndex], ...updateData };
        await env.VISITS.put(`user:${userId}`, JSON.stringify(visits));

        return new Response(JSON.stringify(visits[visitIndex]), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Delete visit
      if (url.pathname.startsWith('/api/visits/') && request.method === 'DELETE') {
        const visitId = url.pathname.split('/')[3];
        
        const existingVisitsData = await env.VISITS.get(`user:${userId}`);
        const visits = existingVisitsData ? JSON.parse(existingVisitsData) : [];
        
        const filteredVisits = visits.filter(v => v.id !== visitId);
        await env.VISITS.put(`user:${userId}`, JSON.stringify(filteredVisits));

        return new Response(JSON.stringify({ success: true }), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Get settings
      if (url.pathname === '/api/settings' && request.method === 'GET') {
        const settingsData = await env.SETTINGS.get(`user:${userId}`);
        const settings = settingsData ? JSON.parse(settingsData) : {};
        
        return new Response(JSON.stringify(settings), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Update settings
      if (url.pathname === '/api/settings' && request.method === 'PUT') {
        const settingsData = await request.json();
        await env.SETTINGS.put(`user:${userId}`, JSON.stringify(settingsData));

        return new Response(JSON.stringify(settingsData), { 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify({
        error: 'Not found'
      }), { 
        status: 404, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });

    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({
        error: 'Internal server error'
      }), { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  },
};