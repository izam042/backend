const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const db = require('../config/db');

// Get cart items
router.get('/', auth, async (req, res) => {
    try {
        const [items] = await db.query(`
            SELECT c.*, b.title, b.author, b.price, b.image_url
            FROM cart c
            JOIN books b ON c.book_id = b.id
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
        `, [req.user.id]);

        // Calculate total
        const total = items.reduce((sum, item) => sum + Number(item.price), 0);

        res.json({ items, total });
    } catch (error) {
        console.error('Error fetching cart items:', error);
        res.status(500).json({ message: 'Error fetching cart items' });
    }
});

// Add item to cart
router.post('/', auth, async (req, res) => {
    try {
        const { bookId } = req.body;

        // Check if book exists and is approved
        const [book] = await db.query(
            'SELECT * FROM books WHERE id = ? AND status = "approved"',
            [bookId]
        );

        if (book.length === 0) {
            return res.status(404).json({ message: 'Book not found or not approved' });
        }

        // Check if book is already in cart
        const [existingItem] = await db.query(
            'SELECT * FROM cart WHERE user_id = ? AND book_id = ?',
            [req.user.id, bookId]
        );

        if (existingItem.length > 0) {
            return res.status(400).json({ message: 'Book already in cart' });
        }

        // Add to cart
        await db.query(
            'INSERT INTO cart (user_id, book_id) VALUES (?, ?)',
            [req.user.id, bookId]
        );

        res.json({ message: 'Book added to cart' });
    } catch (error) {
        console.error('Error adding to cart:', error);
        res.status(500).json({ message: 'Error adding to cart' });
    }
});

// Remove item from cart
router.delete('/:bookId', auth, async (req, res) => {
    try {
        const { bookId } = req.params;

        // Check if item exists in cart
        const [item] = await db.query(
            'SELECT * FROM cart WHERE user_id = ? AND book_id = ?',
            [req.user.id, bookId]
        );

        if (item.length === 0) {
            return res.status(404).json({ message: 'Item not found in cart' });
        }

        // Remove from cart
        await db.query(
            'DELETE FROM cart WHERE user_id = ? AND book_id = ?',
            [req.user.id, bookId]
        );

        res.json({ message: 'Item removed from cart' });
    } catch (error) {
        console.error('Error removing from cart:', error);
        res.status(500).json({ message: 'Error removing from cart' });
    }
});

module.exports = router; 