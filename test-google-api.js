require('dotenv').config();
const { OAuth2Client } = require('google-auth-library');

// This is a simple test script to verify Google API access
async function testGoogleAPI() {
  console.log('\n=== Google API Test ===\n');
  
  // Check if Google Client ID is properly set
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    console.error('❌ ERROR: GOOGLE_CLIENT_ID is not set in environment variables');
    process.exit(1);
  }
  
  console.log('✅ GOOGLE_CLIENT_ID is set:', clientId.substring(0, 10) + '...');
  
  // Initialize OAuth2Client
  try {
    const client = new OAuth2Client(clientId);
    console.log('✅ OAuth2Client initialized successfully');
    
    // Provide information about token verification
    console.log('\nToken Verification Process:');
    console.log('1. When a user signs in with Google, your frontend receives an ID token');
    console.log('2. Your server verifies this token using OAuth2Client.verifyIdToken()');
    console.log('3. If valid, the token payload contains user info (email, name, picture)');
    
    console.log('\nGoogle People API:');
    console.log('- You\'ve enabled the Google People API, which allows access to more detailed profile info');
    console.log('- For basic sign-in, the default ID token already contains essential user data');
    console.log('- The People API is needed only if you require additional profile details');
    
    console.log('\nCommon ID Token Fields:');
    console.log('- sub: The unique Google ID for the user');
    console.log('- email: The user\'s email address');
    console.log('- email_verified: Whether the email is verified (true/false)');
    console.log('- name: The user\'s full name');
    console.log('- given_name: The user\'s first name');
    console.log('- family_name: The user\'s last name');
    console.log('- picture: URL to the user\'s profile picture');
    
    console.log('\nTroubleshooting:');
    console.log('1. Check browser console for any JavaScript errors');
    console.log('2. Verify network requests to /api/auth/google endpoint');
    console.log('3. Review server logs for token verification errors');
    console.log('4. Ensure your Google Cloud Console project has:');
    console.log('   - OAuth consent screen configured and published');
    console.log('   - Correct authorized JavaScript origins');
    console.log('   - Google Identity Services API enabled');
    console.log('   - Google People API enabled');
    
    console.log('\n✅ Test script completed successfully');
    
  } catch (error) {
    console.error('❌ ERROR initializing OAuth2Client:', error.message);
    process.exit(1);
  }
}

// Run the test
testGoogleAPI(); 