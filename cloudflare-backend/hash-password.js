// Simple script to hash password for KV storage
import crypto from 'crypto';

async function hashPasswordNew(password, username) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + username);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer));
}

// Hash the password
const password = "Reservedness5050-propjoe";
const username = "dkarpay";

hashPasswordNew(password, username).then(hash => {
  console.log('Password hash array:', JSON.stringify(hash));
  
  const user = {
    id: "550e8400-e29b-41d4-a716-446655440000",
    username: "dkarpay",
    password: hash,
    email: "dkarpay@pd15.org",
    verified: true,
    createdAt: Date.now()
  };
  
  console.log('Complete user object:', JSON.stringify(user));
}).catch(console.error);