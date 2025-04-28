const pool = require('./config/db');

async function updateSchema() {
  try {
    console.log('Starting database schema update...');
    
    // Check if the users table has auth_provider column
    const [columns] = await pool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'users' 
      AND COLUMN_NAME = 'auth_provider'
    `);
    
    // Add auth_provider if it doesn't exist
    if (columns.length === 0) {
      console.log('Adding auth_provider column to users table');
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN auth_provider VARCHAR(20) DEFAULT 'local'
      `);
    }
    
    // Check if the users table has profile_picture column
    const [pictureColumns] = await pool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'users' 
      AND COLUMN_NAME = 'profile_picture'
    `);
    
    // Add profile_picture if it doesn't exist
    if (pictureColumns.length === 0) {
      console.log('Adding profile_picture column to users table');
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN profile_picture VARCHAR(255) DEFAULT NULL
      `);
    }
    
    // Make password nullable for Google auth users
    const [passwordColumns] = await pool.query(`
      SELECT IS_NULLABLE 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'users' 
      AND COLUMN_NAME = 'password'
    `);
    
    if (passwordColumns.length > 0 && passwordColumns[0].IS_NULLABLE === 'NO') {
      console.log('Making password column nullable for Google auth users');
      await pool.query(`
        ALTER TABLE users 
        MODIFY COLUMN password VARCHAR(255) NULL
      `);
    }
    
    console.log('Database schema update completed');
  } catch (error) {
    console.error('Error updating schema:', error);
  } finally {
    process.exit();
  }
}

updateSchema(); 