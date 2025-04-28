require('dotenv').config();
const { OAuth2Client } = require('google-auth-library');

// Main function for diagnostics
async function checkGoogleConfig() {
  console.log('\n=== Google Authentication Configuration Check ===\n');
  
  // 1. Check if Google Client ID is properly set
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    console.error('❌ ERROR: GOOGLE_CLIENT_ID is not set in environment variables');
    process.exit(1);
  }
  
  console.log('✅ GOOGLE_CLIENT_ID is set:', clientId.substring(0, 10) + '...');
  
  // 2. Check if Google OAuth Client can be initialized
  try {
    const client = new OAuth2Client(clientId);
    console.log('✅ OAuth2Client initialized successfully');
    
    // Print client type and check for basic methods
    console.log('Client type:', typeof client);
    console.log('Has verifyIdToken method:', typeof client.verifyIdToken === 'function');
  } catch (error) {
    console.error('❌ ERROR: Failed to initialize OAuth2Client:', error.message);
    process.exit(1);
  }
  
  // 3. Check if google-auth-library is properly installed
  try {
    const packageInfo = require('./package.json');
    const dependencies = packageInfo.dependencies || {};
    
    if (dependencies['google-auth-library']) {
      console.log('✅ google-auth-library is installed, version:', dependencies['google-auth-library']);
    } else {
      console.warn('⚠️ WARNING: google-auth-library is not listed in package.json dependencies');
    }
  } catch (error) {
    console.warn('⚠️ WARNING: Could not read package.json:', error.message);
  }
  
  // 4. Provide guidance
  console.log('\n=== Google Authentication Troubleshooting Guide ===\n');
  console.log('If you are seeing issues with Google Sign-In, check the following:');
  console.log('1. Ensure your Google Client ID matches between frontend and backend');
  console.log('2. Verify that your app is properly configured in Google Cloud Console');
  console.log('3. Make sure the OAuth consent screen is published and not in testing mode');
  console.log('4. Check that your domain is added to Authorized JavaScript Origins');
  console.log('5. Verify that you are requesting email, profile, and openid scopes');
  console.log('6. Try signing in with a different Google account');
  
  console.log('\nCurrent configuration in login.html:');
  console.log('- Client ID should match:', clientId);
  console.log('- Should request scopes: openid email profile');
  console.log('- Should have prompt: select_account');
  console.log('- Should have UX mode: popup');
  
  console.log('\n=== End of Diagnostic Check ===\n');
}

// Run the function
checkGoogleConfig(); 