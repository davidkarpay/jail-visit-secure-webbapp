// Cleanup script to delete specific test accounts
// Run this with: wrangler dev --local --persist-to ./dev-storage

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    if (url.pathname === '/cleanup' && request.method === 'POST') {
      const usernamesToDelete = ['dkarpay', 'dkarpay@pd15.org'];
      const deletedUsers = [];
      
      for (const username of usernamesToDelete) {
        try {
          // Delete main user record
          const userExists = await env.USERS.get(`user:${username}`);
          if (userExists) {
            await env.USERS.delete(`user:${username}`);
            deletedUsers.push(username);
            console.log(`Deleted user: ${username}`);
          }
          
          // Delete any pending verification
          await env.PENDING_USERS.delete(`verify:${username}`);
          
          // Delete any login pins
          await env.LOGIN_PINS.delete(`pin:${username}`);
          
          // Delete any reset codes
          await env.RESET_CODES.delete(`reset:${username}`);
          
          console.log(`Cleaned up all records for: ${username}`);
          
        } catch (error) {
          console.error(`Error deleting ${username}:`, error);
        }
      }
      
      return new Response(JSON.stringify({
        message: `Cleanup complete`,
        deletedUsers: deletedUsers,
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response('Cleanup endpoint - POST to /cleanup', {
      headers: { 'Content-Type': 'text/plain' }
    });
  }
};
