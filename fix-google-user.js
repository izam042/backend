require('dotenv').config();
const pool = require('./config/db');

async function fixGoogleUsers() {
  try {
    console.log('Connecting to database...');
    
    // 1. Check if the auth_provider column exists, add it if not
    const [columns] = await pool.query('SHOW COLUMNS FROM users LIKE "auth_provider"');
    if (columns.length === 0) {
      console.log('Adding auth_provider column to users table...');
      await pool.query('ALTER TABLE users ADD COLUMN auth_provider VARCHAR(20) DEFAULT "local"');
    }
    
    // 2. Check if the profile_picture column exists, add it if not
    const [pictureColumns] = await pool.query('SHOW COLUMNS FROM users LIKE "profile_picture"');
    if (pictureColumns.length === 0) {
      console.log('Adding profile_picture column to users table...');
      await pool.query('ALTER TABLE users ADD COLUMN profile_picture VARCHAR(255) NULL');
    }
    
    // 3. Make password column nullable for Google auth users
    await pool.query('ALTER TABLE users MODIFY password VARCHAR(255) NULL');
    
    // 4. Find all users, focus on any with Google User as name or missing auth_provider
    const [users] = await pool.query('SELECT * FROM users');
    console.log(`Found ${users.length} users in the database.`);
    
    // 5. Log all users for debugging
    console.log('Users:');
    users.forEach((user, index) => {
      console.log(`[${index+1}] ID: ${user.id}, Name: ${user.name}, Email: ${user.email}, Auth: ${user.auth_provider || 'null'}`);
    });
    
    // 6. Fix any Google User names by using the email username
    let updatedCount = 0;
    for (const user of users) {
      let needsUpdate = false;
      const updates = [];
      const values = [];
      
      // Fix Google User name
      if (user.name === 'Google User' || !user.name) {
        const emailName = user.email.split('@')[0];
        const capitalizedName = emailName.charAt(0).toUpperCase() + emailName.slice(1);
        updates.push('name = ?');
        values.push(capitalizedName);
        needsUpdate = true;
      }
      
      // Set auth_provider if missing
      if (!user.auth_provider) {
        updates.push('auth_provider = ?');
        values.push('google');  // Assume missing auth_provider for existing users is Google
        needsUpdate = true;
      }
      
      if (needsUpdate) {
        values.push(user.id);
        const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
        await pool.query(query, values);
        updatedCount++;
      }
    }
    
    console.log(`Updated ${updatedCount} users.`);
    
    // 7. Verify the fixes
    const [updatedUsers] = await pool.query('SELECT id, email, name, role, auth_provider FROM users');
    console.log('\nUpdated users:');
    updatedUsers.forEach((user, index) => {
      console.log(`[${index+1}] ID: ${user.id}, Name: ${user.name}, Email: ${user.email}, Auth: ${user.auth_provider || 'null'}`);
    });
    
    console.log('\nFix completed successfully!');
    process.exit(0);
  } catch (err) {
    console.error('Error fixing Google users:', err);
    process.exit(1);
  }
}

// Run the fix function
fixGoogleUsers(); 