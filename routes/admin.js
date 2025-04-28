const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { auth } = require('../middleware/auth');

// Admin middleware to check if user is admin
const admin = async (req, res, next) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied. Admin only.' });
        }
        next();
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Apply admin middleware to all routes
router.use(auth, admin);

// Get dashboard statistics
router.get('/stats', async (req, res) => {
    try {
        const [users] = await db.query('SELECT COUNT(*) as count FROM users WHERE role != "admin"');
        const [books] = await db.query('SELECT COUNT(*) as count FROM books');
        const [orders] = await db.query('SELECT COUNT(*) as count FROM orders');
        const [pendingSellers] = await db.query('SELECT COUNT(*) as count FROM seller_info WHERE approved = false');

        res.json({
            totalUsers: users[0].count,
            totalBooks: books[0].count,
            totalOrders: orders[0].count,
            pendingSellers: pendingSellers[0].count
        });
    } catch (error) {
        console.error('Error getting dashboard stats:', error);
        res.status(500).json({ message: 'Error getting dashboard statistics' });
    }
});

// User management
router.get('/users', async (req, res) => {
    try {
        const search = req.query.search || '';
        const [users] = await db.query(
            `SELECT id, name, email, role, status 
             FROM users 
             WHERE name LIKE ? OR email LIKE ?
             ORDER BY id DESC`,
            [`%${search}%`, `%${search}%`]
        );
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users' });
    }
});

router.get('/users/:id', async (req, res) => {
    try {
        const [users] = await db.query(
            'SELECT id, name, email, role, status FROM users WHERE id = ?',
            [req.params.id]
        );
        if (users.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(users[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user' });
    }
});

router.post('/users', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Validate input
        if (!name || !email || !password || !role) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if email exists
        const [existingUsers] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const [result] = await db.query(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, role]
        );

        res.status(201).json({
            id: result.insertId,
            name,
            email,
            role
        });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user' });
    }
});

router.put('/users/:id', async (req, res) => {
    try {
        const { name, email, password, role, status } = req.body;
        const userId = req.params.id;

        // Check if user exists
        const [existingUsers] = await db.query('SELECT id FROM users WHERE id = ?', [userId]);
        if (existingUsers.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Build update query
        let query = 'UPDATE users SET name = ?, email = ?, role = ?';
        let params = [name, email, role];

        if (status) {
            query += ', status = ?';
            params.push(status);
        }

        if (password) {
            query += ', password = ?';
            const hashedPassword = await bcrypt.hash(password, 10);
            params.push(hashedPassword);
        }

        query += ' WHERE id = ?';
        params.push(userId);

        await db.query(query, params);
        res.json({ message: 'User updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating user' });
    }
});

router.delete('/users/:id', async (req, res) => {
    try {
        const [result] = await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting user' });
    }
});

// Book management
router.get('/books', async (req, res) => {
    try {
        const { status = 'pending' } = req.query;
        const [books] = await db.query(`
            SELECT b.*, u.name as seller_name, u.email as seller_email 
            FROM books b 
            JOIN users u ON b.seller_id = u.id 
            WHERE b.status = ?
        `, [status]);
        res.json(books);
    } catch (error) {
        console.error('Error getting books:', error);
        res.status(500).json({ message: 'Error getting books' });
    }
});

router.delete('/books/:id', async (req, res) => {
    try {
        const [result] = await db.query('DELETE FROM books WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Book not found' });
        }
        res.json({ message: 'Book deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting book' });
    }
});

// Order management
router.get('/orders', async (req, res) => {
    try {
        const { search, status } = req.query;
        let query = `
            SELECT o.*, 
                   b.title as book_title,
                   buyer.name as buyer_name,
                   seller.name as seller_name
            FROM orders o
            JOIN books b ON o.book_id = b.id
            JOIN users buyer ON o.buyer_id = buyer.id
            JOIN users seller ON b.seller_id = seller.id
            WHERE 1=1
        `;
        const params = [];

        if (search) {
            query += ' AND (b.title LIKE ? OR buyer.name LIKE ? OR seller.name LIKE ?)';
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }

        if (status) {
            query += ' AND o.status = ?';
            params.push(status);
        }

        query += ' ORDER BY o.id DESC';

        const [orders] = await db.query(query, params);
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching orders' });
    }
});

router.get('/orders/:id', async (req, res) => {
    try {
        const [orders] = await db.query(
            `SELECT o.*, 
                    b.title as book_title, b.author, b.price,
                    buyer.name as buyer_name, buyer.email as buyer_email,
                    seller.name as seller_name, seller.email as seller_email
             FROM orders o
             JOIN books b ON o.book_id = b.id
             JOIN users buyer ON o.buyer_id = buyer.id
             JOIN users seller ON b.seller_id = seller.id
             WHERE o.id = ?`,
            [req.params.id]
        );

        if (orders.length === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        res.json(orders[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching order' });
    }
});

router.put('/orders/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const orderId = req.params.id;

        // Validate status
        const validStatuses = ['PENDING', 'APPROVED', 'COMPLETED', 'CANCELLED'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }

        // Update order status
        const [result] = await db.query(
            'UPDATE orders SET status = ? WHERE id = ?',
            [status, orderId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        // If order is approved or cancelled, update book status
        if (status === 'APPROVED') {
            await db.query(
                `UPDATE books b 
                 JOIN orders o ON b.id = o.book_id 
                 SET b.status = 'pending' 
                 WHERE o.id = ?`,
                [orderId]
            );
        } else if (status === 'CANCELLED') {
            await db.query(
                `UPDATE books b 
                 JOIN orders o ON b.id = o.book_id 
                 SET b.status = 'available' 
                 WHERE o.id = ?`,
                [orderId]
            );
        }

        res.json({ message: 'Order status updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating order status' });
    }
});

// @route   GET /api/admin/pending-sellers
// @desc    Get pending seller applications
// @access  Private/Admin
router.get('/pending-sellers', async (req, res) => {
    try {
        const [sellers] = await db.query(`
            SELECT u.id, u.name, u.email, si.phone, si.city, si.state
            FROM users u
            JOIN seller_info si ON u.id = si.user_id
            WHERE si.approved = false
            ORDER BY si.created_at DESC
        `);

        res.json(sellers);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// @route   GET /api/admin/pending-books
// @desc    Get pending book listings
// @access  Private/Admin
router.get('/pending-books', async (req, res) => {
    try {
        const [books] = await db.query(`
            SELECT b.*, u.name as seller_name
            FROM books b
            JOIN users u ON b.seller_id = u.id
            WHERE b.status = 'pending'
            ORDER BY b.created_at DESC
        `);

        res.json(books);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// @route   PUT /api/admin/sellers/:id/approve
// @desc    Approve a seller application
// @access  Private/Admin
router.put('/sellers/:id/approve', async (req, res) => {
    try {
        const { id } = req.params;
        
        await db.query('UPDATE seller_info SET approved = true WHERE user_id = ?', [id]);
        await db.query('UPDATE users SET role = ? WHERE id = ?', ['seller', id]);

        res.json({ message: 'Seller approved successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// @route   PUT /api/admin/sellers/:id/reject
// @desc    Reject a seller application
// @access  Private/Admin
router.put('/sellers/:id/reject', async (req, res) => {
    try {
        const { id } = req.params;
        
        await db.query('DELETE FROM seller_info WHERE user_id = ?', [id]);
        await db.query('UPDATE users SET role = ? WHERE id = ?', ['buyer', id]);

        res.json({ message: 'Seller rejected successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// @route   PUT /api/admin/books/:id/approve
// @desc    Approve a book listing
// @access  Private/Admin
router.post('/books/:id/approve', async (req, res) => {
    try {
        const { id } = req.params;
        await db.query(
            'UPDATE books SET status = "approved" WHERE id = ?',
            [id]
        );
        res.json({ message: 'Book listing approved' });
    } catch (error) {
        console.error('Error approving book listing:', error);
        res.status(500).json({ message: 'Error approving book listing' });
    }
});

// @route   PUT /api/admin/books/:id/reject
// @desc    Reject a book listing
// @access  Private/Admin
router.post('/books/:id/reject', async (req, res) => {
    try {
        const { id } = req.params;
        await db.query(
            'UPDATE books SET status = "rejected" WHERE id = ?',
            [id]
        );
        res.json({ message: 'Book listing rejected' });
    } catch (error) {
        console.error('Error rejecting book listing:', error);
        res.status(500).json({ message: 'Error rejecting book listing' });
    }
});

// Get seller applications
router.get('/seller-applications', async (req, res) => {
    try {
        const [applications] = await db.query(`
            SELECT si.*, u.name, u.email 
            FROM seller_info si 
            JOIN users u ON si.user_id = u.id 
            WHERE si.approved = false
        `);
        res.json(applications);
    } catch (error) {
        console.error('Error getting seller applications:', error);
        res.status(500).json({ message: 'Error getting seller applications' });
    }
});

// Approve seller application
router.post('/seller-applications/:id/approve', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Start transaction
        await db.query('START TRANSACTION');

        // Update seller_info
        await db.query(
            'UPDATE seller_info SET approved = true WHERE id = ?',
            [id]
        );

        // Get user_id from seller_info
        const [sellerInfo] = await db.query(
            'SELECT user_id FROM seller_info WHERE id = ?',
            [id]
        );

        // Update user role
        await db.query(
            'UPDATE users SET role = "seller" WHERE id = ?',
            [sellerInfo[0].user_id]
        );

        await db.query('COMMIT');
        res.json({ message: 'Seller application approved' });
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error approving seller application:', error);
        res.status(500).json({ message: 'Error approving seller application' });
    }
});

// Reject seller application
router.post('/seller-applications/:id/reject', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Start transaction
        await db.query('START TRANSACTION');

        // Get user_id from seller_info
        const [sellerInfo] = await db.query(
            'SELECT user_id FROM seller_info WHERE id = ?',
            [id]
        );

        // Delete seller_info
        await db.query(
            'DELETE FROM seller_info WHERE id = ?',
            [id]
        );

        // Update user role back to buyer
        await db.query(
            'UPDATE users SET role = "buyer" WHERE id = ?',
            [sellerInfo[0].user_id]
        );

        await db.query('COMMIT');
        res.json({ message: 'Seller application rejected' });
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error rejecting seller application:', error);
        res.status(500).json({ message: 'Error rejecting seller application' });
    }
});

module.exports = router; 