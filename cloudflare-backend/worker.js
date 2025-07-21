// Cloudflare Worker API for Jail Visit Logger
// This handles authentication and data storage using KV

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
      // Register new user
      if (path === '/api/register' && request.method === 'POST') {
        const { username, password } = await request.json();
        
        if (!username || !password) {
          return new Response(JSON.stringify({ error: 'Username and password required' }), {
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

        // Create user
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const saltStr = btoa(String.fromCharCode(...salt));
        const hashedPassword = await hashPassword(password, saltStr);
        
        const user = {
          id: crypto.randomUUID(),
          username,
          password: hashedPassword,
          salt: saltStr,
          createdAt: new Date().toISOString()
        };

        await env.USERS.put(`user:${username}`, JSON.stringify(user));
        
        // Generate token
        const token = await generateJWT(user.id, env.JWT_SECRET || 'your-secret-key');
        
        return new Response(JSON.stringify({ token, userId: user.id }), {
          headers: corsHeaders
        });
      }

      // Login
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