/**
 * Token management for Microsoft Graph API authentication
 */
const fs = require('fs');
const config = require('../config');
const https = require('https');
const querystring = require('querystring');

// Global variable to store tokens
let cachedTokens = null;

/**
 * Loads authentication tokens from the token file
 * @returns {object|null} - The loaded tokens or null if not available
 */
function loadTokenCache() {
  try {
    const tokenPath = config.AUTH_CONFIG.tokenStorePath;
    console.error(`[DEBUG] Attempting to load tokens from: ${tokenPath}`);
    console.error(`[DEBUG] HOME directory: ${process.env.HOME}`);
    console.error(`[DEBUG] Full resolved path: ${tokenPath}`);
    
    // Log file existence and details
    if (!fs.existsSync(tokenPath)) {
      console.error('[DEBUG] Token file does not exist');
      return null;
    }
    
    const stats = fs.statSync(tokenPath);
    console.error(`[DEBUG] Token file stats:
      Size: ${stats.size} bytes
      Created: ${stats.birthtime}
      Modified: ${stats.mtime}`);
    
    const tokenData = fs.readFileSync(tokenPath, 'utf8');
    console.error('[DEBUG] Token file contents length:', tokenData.length);
    console.error('[DEBUG] Token file first 200 characters:', tokenData.slice(0, 200));
    
    try {
      const tokens = JSON.parse(tokenData);
      console.error('[DEBUG] Parsed tokens keys:', Object.keys(tokens));
      
      // Log each key's value to see what's present
      Object.keys(tokens).forEach(key => {
        console.error(`[DEBUG] ${key}: ${typeof tokens[key]}`);
      });
      
      // Check for access token presence
      if (!tokens.access_token) {
        console.error('[DEBUG] No access_token found in tokens');
        return null;
      }
      
      // Check token expiration
      const now = Date.now();
      const expiresAt = tokens.expires_at || 0;
      
      console.error(`[DEBUG] Current time: ${now}`);
      console.error(`[DEBUG] Token expires at: ${expiresAt}`);
      
      // Update the cache
      cachedTokens = tokens;
      return tokens;
    } catch (parseError) {
      console.error('[DEBUG] Error parsing token JSON:', parseError);
      return null;
    }
  } catch (error) {
    console.error('[DEBUG] Error loading token cache:', error);
    return null;
  }
}

/**
 * Saves authentication tokens to the token file
 * @param {object} tokens - The tokens to save
 * @returns {boolean} - Whether the save was successful
 */
function saveTokenCache(tokens) {
  try {
    const tokenPath = config.AUTH_CONFIG.tokenStorePath;
    console.error(`Saving tokens to: ${tokenPath}`);
    
    fs.writeFileSync(tokenPath, JSON.stringify(tokens, null, 2));
    console.error('Tokens saved successfully');
    
    // Update the cache
    cachedTokens = tokens;
    return true;
  } catch (error) {
    console.error('Error saving token cache:', error);
    return false;
  }
}

/**
 * Gets the current access token, loading from cache if necessary
 * @returns {string|null} - The access token or null if not available
 */
function getAccessToken() {
  if (cachedTokens && cachedTokens.access_token) {
    // Check if token is about to expire (within 5 minutes)
    const now = Date.now();
    const expiresAt = cachedTokens.expires_at || 0;
    
    if (now > expiresAt - (5 * 60 * 1000)) {
      console.error('[DEBUG] Token expired or about to expire, attempting refresh');
      // Try to refresh the token
      return refreshAccessToken()
        .then(newToken => {
          return newToken;
        })
        .catch(error => {
          console.error('[DEBUG] Token refresh failed:', error.message);
          return null;
        });
    }
    
    return cachedTokens.access_token;
  }
  
  const tokens = loadTokenCache();
  if (!tokens) return null;
  
  // Check if token is about to expire (within 5 minutes)
  const now = Date.now();
  const expiresAt = tokens.expires_at || 0;
  
  if (now > expiresAt - (5 * 60 * 1000)) {
    console.error('[DEBUG] Loaded token expired or about to expire, attempting refresh');
    // Try to refresh the token
    return refreshAccessToken()
      .then(newToken => {
        return newToken;
      })
      .catch(error => {
        console.error('[DEBUG] Token refresh failed:', error.message);
        return null;
      });
  }
  
  return tokens.access_token;
}

/**
 * Refreshes the access token using the refresh token
 * @returns {Promise<string>} - The new access token
 */
function refreshAccessToken() {
  return new Promise((resolve, reject) => {
    const tokens = loadTokenCache();
    
    if (!tokens || !tokens.refresh_token) {
      reject(new Error('No refresh token available'));
      return;
    }
    
    console.error('[DEBUG] Attempting to refresh token');
    
    const postData = querystring.stringify({
      client_id: config.AUTH_CONFIG.clientId,
      client_secret: config.AUTH_CONFIG.clientSecret,
      refresh_token: tokens.refresh_token,
      grant_type: 'refresh_token',
      scope: config.AUTH_CONFIG.scopes.join(' ')
    });
    
    const options = {
      hostname: 'login.microsoftonline.com',
      path: '/common/oauth2/v2.0/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    const req = https.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const tokenResponse = JSON.parse(data);
            
            // Calculate expiration time (current time + expires_in seconds)
            const expiresAt = Date.now() + (tokenResponse.expires_in * 1000);
            
            // Add expires_at for easier expiration checking
            tokenResponse.expires_at = expiresAt;
            
            // Preserve the refresh token if one wasn't returned
            if (!tokenResponse.refresh_token && tokens.refresh_token) {
              tokenResponse.refresh_token = tokens.refresh_token;
            }
            
            // Save tokens to file
            saveTokenCache(tokenResponse);
            console.error('[DEBUG] Token refreshed successfully');
            
            resolve(tokenResponse.access_token);
          } catch (error) {
            reject(new Error(`Error parsing token response: ${error.message}`));
          }
        } else {
          reject(new Error(`Token refresh failed with status ${res.statusCode}: ${data}`));
        }
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.write(postData);
    req.end();
  });
}

/**
 * Creates a test access token for use in test mode
 * @returns {object} - The test tokens
 */
function createTestTokens() {
  const testTokens = {
    access_token: "test_access_token_" + Date.now(),
    refresh_token: "test_refresh_token_" + Date.now(),
    expires_at: Date.now() + (3600 * 1000) // 1 hour
  };
  
  saveTokenCache(testTokens);
  return testTokens;
}

module.exports = {
  loadTokenCache,
  saveTokenCache,
  getAccessToken,
  createTestTokens,
  refreshAccessToken
};
