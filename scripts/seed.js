const bcrypt = require('bcryptjs');
const pool = require('../config/db');

async function seedDatabase() {
    try {
        // Clear existing data
        await pool.query('SET FOREIGN_KEY_CHECKS = 0');
        await pool.query('TRUNCATE TABLE orders');
        await pool.query('TRUNCATE TABLE books');
        await pool.query('TRUNCATE TABLE users');
        await pool.query('SET FOREIGN_KEY_CHECKS = 1');

        // Create admin user
        const adminPassword = await bcrypt.hash('admin123', 10);
        await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            ['Admin User', 'admin@shelfswap.com', adminPassword, 'admin']
        );

        // Hash password for other users
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('password123', salt);

        // Insert regular users
        const [userResult] = await pool.query(`
            INSERT INTO users (email, password, name, role) VALUES
            ('seller1@example.com', ?, 'John Seller', 'seller'),
            ('seller2@example.com', ?, 'Jane Seller', 'seller'),
            ('buyer1@example.com', ?, 'Alice Buyer', 'buyer'),
            ('buyer2@example.com', ?, 'Bob Buyer', 'buyer')
        `, [hashedPassword, hashedPassword, hashedPassword, hashedPassword]);

        // Insert books
        const [bookResult] = await pool.query(`
            INSERT INTO books (title, author, description, price, \`condition\`, category, seller_id, status) VALUES
            -- JEE Books
            ('Physics for JEE Main & Advanced', 'H.C. Verma', 'Comprehensive physics book for JEE preparation', 499.99, 'good', 'JEE', 2, 'approved'),
            ('Mathematics for JEE', 'R.D. Sharma', 'Complete mathematics guide for JEE', 599.99, 'like_new', 'JEE', 2, 'approved'),
            ('Chemistry for JEE', 'O.P. Tandon', 'Detailed chemistry book for JEE preparation', 449.99, 'good', 'JEE', 3, 'approved'),
            
            -- NEET Books
            ('Biology for NEET', 'Pradeep', 'Complete biology guide for NEET', 699.99, 'new', 'NEET', 2, 'approved'),
            ('Physics for NEET', 'D.C. Pandey', 'NEET physics preparation book', 549.99, 'good', 'NEET', 3, 'approved'),
            ('Chemistry for NEET', 'N. Awasthi', 'Comprehensive chemistry for NEET', 499.99, 'like_new', 'NEET', 2, 'approved'),
            
            -- CUET Books
            ('General Knowledge for CUET', 'Arihant', 'Complete GK guide for CUET', 299.99, 'new', 'CUET', 3, 'approved'),
            ('English for CUET', 'Wren & Martin', 'English language preparation for CUET', 399.99, 'good', 'CUET', 2, 'approved'),
            ('Mathematics for CUET', 'R.S. Aggarwal', 'Mathematics preparation for CUET', 349.99, 'like_new', 'CUET', 3, 'approved'),
            
            -- Boards Books
            ('Physics for Class 12', 'NCERT', 'Class 12 Physics textbook', 199.99, 'good', 'Boards', 2, 'approved'),
            ('Chemistry for Class 12', 'NCERT', 'Class 12 Chemistry textbook', 199.99, 'good', 'Boards', 3, 'approved'),
            ('Mathematics for Class 12', 'NCERT', 'Class 12 Mathematics textbook', 199.99, 'like_new', 'Boards', 2, 'approved'),
            
            -- Olympiad Books
            ('Science Olympiad Guide', 'MTG', 'Complete guide for Science Olympiad', 599.99, 'new', 'Olympiad', 3, 'approved'),
            ('Mathematics Olympiad Guide', 'MTG', 'Complete guide for Mathematics Olympiad', 599.99, 'good', 'Olympiad', 2, 'approved'),
            ('Physics Olympiad Guide', 'MTG', 'Complete guide for Physics Olympiad', 599.99, 'like_new', 'Olympiad', 3, 'approved')
        `);

        // Insert orders
        await pool.query(`
            INSERT INTO orders (buyer_id, book_id, seller_id, status, price) VALUES
            (4, 1, 2, 'completed', 499.99),
            (4, 4, 2, 'completed', 699.99),
            (5, 2, 2, 'pending', 599.99),
            (5, 7, 3, 'completed', 299.99)
        `);

        console.log('Database seeded successfully!');
    } catch (err) {
        console.error('Error seeding database:', err);
        process.exit(1);
    }
}

seedDatabase(); 