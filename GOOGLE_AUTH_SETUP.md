# Google Sign-In Setup Guide

## 1. Create Google OAuth 2.0 Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Web application" as the application type
6. Give your client a name (e.g., "ShelfSwap Web Client")
7. Add authorized JavaScript origins:
   - For development: `http://localhost:5000` (use your actual port)
   - For production: `https://your-domain.com`
8. Add authorized redirect URIs:
   - For development: `http://localhost:5000`
   - For production: `https://your-domain.com`
9. Click "Create"

## 2. Update Your Application Configuration

1. Copy your Client ID from the Google Cloud Console

2. Update the `.env` file with your Google Client ID:
   ```
   GOOGLE_CLIENT_ID=your-client-id-here
   ```

3. Update the login.html and register.html files:
   Replace `YOUR_GOOGLE_CLIENT_ID` with your actual client ID in:
   ```html
   data-client_id="YOUR_GOOGLE_CLIENT_ID"
   ```

## 3. Testing the Integration

1. Make sure you've installed the required package:
   ```
   npm install google-auth-library
   ```

2. Start your application and test the Sign-In flow:
   ```
   npm start
   ```

3. Navigate to the login or register page and try signing in with Google

## 4. Troubleshooting

If you encounter issues:

1. Check the browser console for errors
2. Verify that your Client ID is correct
3. Make sure your authorized origins match your actual application URL
4. Verify that the `GOOGLE_CLIENT_ID` is properly set in your environment
5. Check server logs for backend verification errors

## 5. Production Considerations

Before going to production:

1. Add your production domain to authorized JavaScript origins in Google Cloud Console
2. Make sure you're using HTTPS for your production site
3. Update the `GOOGLE_CLIENT_ID` in your production environment
4. Test the flow on your production environment after deployment 