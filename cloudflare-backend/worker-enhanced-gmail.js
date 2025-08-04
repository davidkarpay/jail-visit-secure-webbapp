// Enhanced Cloudflare Worker API for JailJogger
// Includes Email verification, PIN login, password reset using Gmail
// Updated to use Gmail API instead of Mailgun

// Helper function to generate 6-digit PIN
function generatePIN() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to send email using Gmail API
async function sendEmail(to, subject, message, env) {
  if (!env.GMAIL_CLIENT_ID || !env.GMAIL_CLIENT_SECRET || !env.GMAIL_REFRESH_TOKEN) {
    console.error('Gmail credentials not configured');
    return false;
  }

  try {
    // Get access token using refresh token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: env.GMAIL_CLIENT_ID,
        client_secret: env.GMAIL_CLIENT_SECRET,
        refresh_token: env.GMAIL_REFRESH_TOKEN,
        grant_type: 'refresh_token',
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      console.error('Failed to get Gmail access token');
      return false;
    }

    // Create email message
    const fromEmail = env.GMAIL_FROM_EMAIL || 'jailjogger@gmail.com';
    const emailContent = [
      `From: JailJogger <${fromEmail}>`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `Content-Type: text/html; charset=UTF-8`,
      '',
      message
    ].join('\r\n');

    // Base64 encode the message
    const encodedMessage = btoa(emailContent)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    // Send email using Gmail API
    const sendResponse = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        raw: encodedMessage,
      }),
    });

    return sendResponse.ok;
  } catch (error) {
    console.error('Gmail send error:', error);
    return false;
  }
}

// Email templates
function getVerificationEmailTemplate(code, username) {
  return `
    <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background: #0a0a0a; color: #e4e4e4; padding: 20px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #3b82f6; margin: 0;">JailJogger</h1>
        <p style="color: #a0a0a0; margin: 5px 0;">Secure Jail Visit Logging</p>
      </div>
      
      <div style="background: #1a1a1a; padding: 25px; border-radius: 8px; border: 1px solid #333;">
        <h2 style="color: #e4e4e4; margin-top: 0;">Verify Your Account</h2>
        <p style="color: #a0a0a0; line-height: 1.6;">
          Hello <strong style="color: #e4e4e4;">${username}</strong>,
        </p>
        <p style="color: #a0a0a0; line-height: 1.6;">
          Thank you for registering with JailJogger. To complete your account setup, please enter this verification code:
        </p>
        
        <div style="text-align: center; margin: 25px 0;">
          <div style="background: #3b82f6; color: white; padding: 15px 25px; border-radius: 8px; font-size: 24px; font-weight: bold; letter-spacing: 3px; display: inline-block;">
            ${code}
          </div>
        </div>
        
        <p style="color: #a0a0a0; line-height: 1.6; font-size: 14px;">
          This code will expire in 15 minutes. If you didn't request this verification, please ignore this email.
        </p>
      </div>
      
      <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
        <p>JailJogger - 15th Judicial Circuit Public Defender Office</p>
      </div>
    </div>
  `;
}

function getPINEmailTemplate(pin, username) {
  return `
    <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background: #0a0a0a; color: #e4e4e4; padding: 20px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #3b82f6; margin: 0;">JailJogger</h1>
        <p style="color: #a0a0a0; margin: 5px 0;">Quick PIN Login</p>
      </div>
      
      <div style="background: #1a1a1a; padding: 25px; border-radius: 8px; border: 1px solid #333;">
        <h2 style="color: #e4e4e4; margin-top: 0;">Your Login PIN</h2>
        <p style="color: #a0a0a0; line-height: 1.6;">
          Hello <strong style="color: #e4e4e4;">${username}</strong>,
        </p>
        <p style="color: #a0a0a0; line-height: 1.6;">
          Here's your one-time login PIN:
        </p>
        
        <div style="text-align: center; margin: 25px 0;">
          <div style="background: #10b981; color: white; padding: 15px 25px; border-radius: 8px; font-size: 24px; font-weight: bold; letter-spacing: 3px; display: inline-block;">
            ${pin}
          </div>
        </div>
        
        <p style="color: #a0a0a0; line-height: 1.6; font-size: 14px;">
          This PIN will expire in 10 minutes. If you didn't request this login, please ignore this email.
        </p>
      </div>
      
      <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
        <p>JailJogger - 15th Judicial Circuit Public Defender Office</p>
      </div>
    </div>
  `;
}

function getPasswordResetEmailTemplate(code, username) {
  return `
    <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; background: #0a0a0a; color: #e4e4e4; padding: 20px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #3b82f6; margin: 0;">JailJogger</h1>
        <p style="color: #a0a0a0; margin: 5px 0;">Password Reset</p>
      </div>
      
      <div style="background: #1a1a1a; padding: 25px; border-radius: 8px; border: 1px solid #333;">
        <h2 style="color: #e4e4e4; margin-top: 0;">Reset Your Password</h2>
        <p style="color: #a0a0a0; line-height: 1.6;">
          Hello <strong style="color: #e4e4e4;">${username}</strong>,
        </p>
        <p style="color: #a0a0a0; line-height: 1.6;">
          You requested a password reset. Use this code to set a new password:
        </p>
        
        <div style="text-align: center; margin: 25px 0;">
          <div style="background: #f59e0b; color: white; padding: 15px 25px; border-radius: 8px; font-size: 24px; font-weight: bold; letter-spacing: 3px; display: inline-block;">
            ${code}
          </div>
        </div>
        
        <p style="color: #a0a0a0; line-height: 1.6; font-size: 14px;">
          This code will expire in 15 minutes. If you didn't request this reset, please ignore this email.
        </p>
      </div>
      
      <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
        <p>JailJogger - 15th Judicial Circuit Public Defender Office</p>
      </div>
    </div>
  `;
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

        // Check if user already exists
        const existingUser = await env.USERS.get(username);
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
        const pendingUser = {
          username,
          password: await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + username)),
          email,
          verificationCode,
          createdAt: Date.now()
        };
        
        await env.PENDING_USERS.put(username, JSON.stringify(pendingUser), { expirationTtl: 900 });
        
        // Send verification email
        const emailSent = await sendEmail(
          email,
          'JailJogger - Verify Your Account',
          getVerificationEmailTemplate(verificationCode, username),
          env
        );
        
        if (!emailSent) {
          return new Response(JSON.stringify({
            error: 'Failed to send verification email'
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
        
        const userData = await env.USERS.get(username);
        if (!userData) {
          return new Response(JSON.stringify({
            error: 'Invalid username or password'
          }), { 
            status: 401, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const user = JSON.parse(userData);
        const hashedPassword = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + username));
        const passwordArray = new Uint8Array(hashedPassword);
        const userPasswordArray = new Uint8Array(user.password);

        if (passwordArray.length !== userPasswordArray.length) {
          return new Response(JSON.stringify({
            error: 'Invalid username or password'
          }), { 
            status: 401, 
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        let isValid = true;
        for (let i = 0; i < passwordArray.length; i++) {
          if (passwordArray[i] !== userPasswordArray[i]) {
            isValid = false;
            break;
          }
        }

        if (!isValid) {
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
        
        const userData = await env.USERS.get(username);
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
          getPINEmailTemplate(pin, username),
          env
        );

        if (!emailSent) {
          return new Response(JSON.stringify({
            error: 'Failed to send PIN email'
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
        
        const userData = await env.USERS.get(username);
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
          getPasswordResetEmailTemplate(resetCode, username),
          env
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
        const userData = await env.USERS.get(username);
        const user = JSON.parse(userData);
        user.password = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(newPassword + username));
        
        await env.USERS.put(username, JSON.stringify(user));
        await env.RESET_CODES.delete(username);

        return new Response(JSON.stringify({
          message: 'Password reset successful!'
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