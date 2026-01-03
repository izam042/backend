const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const pool = require('../config/db');
const { auth } = require('../middleware/auth');
const { OAuth2Client } = require('google-auth-library');

// Initialize Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);


router.post('/register', [
  body('email').isEmail().withMessage('Please enter a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('name').notEmpty().withMessage('Name is required'),
  body('role').isIn(['buyer', 'seller']).withMessage('Role must be either buyer or seller')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name, role } = req.body;

    // Check if user already exists
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const [result] = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, name, role]
    );

    // Get the created user
    const [newUser] = await pool.query(
      'SELECT id, email, name, role FROM users WHERE id = ?',
      [result.insertId]
    );

    // Generate token
    const token = jwt.sign(
      { id: newUser[0].id, email: newUser[0].email, role: newUser[0].role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.json({
      token,
      user: newUser[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', [
  body('email').isEmail().withMessage('Please enter a valid email'),
  body('password').exists().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const user = users[0];

    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    // Return user data along with token
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', auth, async (req, res) => {
  try {
    console.log('Getting user profile for id:', req.user.id);
    const [users] = await pool.query(
      'SELECT id, email, name, role, created_at, profile_picture, auth_provider FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('User profile retrieved:', users[0]);
    res.json(users[0]);
  } catch (err) {
    console.error('Error fetching user profile:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/auth/google
// @desc    Authenticate with Google
// @access  Public
router.post('/google', async (req, res) => {
  try {
    const { idToken } = req.body;
    
    console.log('Google auth request received:', { 
      hasIdToken: !!idToken, 
      tokenLength: idToken ? idToken.length : 0,
      timestamp: new Date().toISOString() // Add timestamp for debugging
    });
    
    if (!idToken) {
      return res.status(400).json({ message: 'ID token is required' });
    }
    
    try {
      // Verify the Google ID token with added logging
      console.log('Verifying token with client ID:', process.env.GOOGLE_CLIENT_ID);
      
      const ticket = await googleClient.verifyIdToken({
        idToken: idToken,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      
      // Get verified user info from the token
      const payload = ticket.getPayload();
      
      // Log detailed payload information for debugging
      console.log('Token verified successfully. Payload keys:', Object.keys(payload));
      console.log('Auth provider:', payload.iss);
      console.log('Subject (user ID):', payload.sub);
      console.log('Email:', payload.email);
      console.log('Email verified:', payload.email_verified);
      console.log('Name:', payload.name);
      console.log('Given name:', payload.given_name);
      console.log('Family name:', payload.family_name);
      console.log('Profile picture:', payload.picture);
      console.log('Locale:', payload.locale);
      
      // Extract user info from payload with stronger validation
      const email = payload.email;
      if (!email) {
        return res.status(400).json({ 
          message: 'Email missing in token',
          details: {
            hasEmail: !!email
          }
        });
      }
      
      // Check email verification status but don't block if not verified
      // Just log a warning instead
      if (!payload.email_verified) {
        console.warn('Warning: Email not verified in Google token:', email);
      }
      
      // Extract name with better fallbacks
      let name = payload.name;
      
      // If name is missing, try to build it from given_name and family_name
      if (!name && (payload.given_name || payload.family_name)) {
        name = [payload.given_name, payload.family_name].filter(Boolean).join(' ');
      }
      
      // Fallback to email username if name is still missing
      if (!name) {
        name = email.split('@')[0]; // Use the part before @ in email as name
        // Capitalize the first letter
        name = name.charAt(0).toUpperCase() + name.slice(1);
      }
      
      const picture = payload.picture;
      const userId = payload.sub; // Google's unique user ID
      
      console.log('Extracted user info:', { email, name, userId, hasPicture: !!picture });
      
      // Check if user already exists
      const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      
      let user;
      
      if (existingUsers.length === 0) {
        console.log('Creating new user from Google auth with email:', email);
        // Create new user if doesn't exist
        const [result] = await pool.query(
          'INSERT INTO users (email, name, role, auth_provider, profile_picture) VALUES (?, ?, ?, ?, ?)',
          [email, name, 'buyer', 'google', picture]
        );
        
        // Get the created user
        const [newUsers] = await pool.query(
          'SELECT id, email, name, role, profile_picture FROM users WHERE id = ?',
          [result.insertId]
        );
        
        user = newUsers[0];
        console.log('New user created:', user);
      } else {
        console.log('User already exists with email:', email);
        // User exists, use existing user
        user = {
          id: existingUsers[0].id,
          email: existingUsers[0].email,
          name: existingUsers[0].name,
          role: existingUsers[0].role,
          profile_picture: existingUsers[0].profile_picture || picture
        };
        
        // Check if we need to update name or profile picture
        let updateFields = [];
        let updateValues = [];
        
        // Always update if user was "Google User" or if Google name is different
        if (
          existingUsers[0].name === 'Google User' || 
          !existingUsers[0].name || 
          (existingUsers[0].auth_provider === 'google' && existingUsers[0].name !== name && name)
        ) {
          console.log('Updating user name from Google profile:', name);
          updateFields.push('name = ?');
          updateValues.push(name);
          user.name = name; // Update the response object too
        }
        
        // Always update profile picture from Google if available
        if (picture && (!existingUsers[0].profile_picture || existingUsers[0].profile_picture !== picture)) {
          console.log('Updating user profile picture from Google');
          updateFields.push('profile_picture = ?');
          updateValues.push(picture);
          user.profile_picture = picture;
        }
        
        // Update auth provider if not already google
        if (existingUsers[0].auth_provider !== 'google') {
          console.log('Updating auth provider to Google');
          updateFields.push('auth_provider = ?');
          updateValues.push('google');
        }
        
        // Perform update if needed
        if (updateFields.length > 0) {
          updateValues.push(user.id);
          await pool.query(
            `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
            updateValues
          );
          console.log('User updated:', user);
        }
      }
      
      // Generate token with more metadata
      const token = jwt.sign(
        { 
          id: user.id, 
          email: user.email, 
          role: user.role,
          auth_provider: 'google',
          google_id: userId
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE }
      );
      
      console.log('Authentication successful, returning user data:', user);
      return res.json({
        token,
        user
      });
    } catch (verifyError) {
      console.error('Error verifying Google token:', verifyError);
      return res.status(401).json({ 
        message: 'Invalid Google token', 
        details: verifyError.message,
        stack: process.env.NODE_ENV === 'development' ? verifyError.stack : undefined
      });
    }
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(500).json({ 
      message: 'Server error during Google authentication',
      details: err.message
    });
  }
});

module.exports = router; 
