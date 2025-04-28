const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const db = require('../config/db');
const multer = require('multer');
const path = require('path');

// Configure multer for image upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'book-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB max file size
    }
});

// Apply to become a seller
router.post('/apply', auth, async (req, res) => {
    try {
        const { phone, address, city, state, pincode } = req.body;
        const userId = req.user.id;

        // Validate required fields
        if (!phone || !address || !city || !state || !pincode) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if user is already a seller
        const [existingSeller] = await db.query(
            'SELECT * FROM seller_info WHERE user_id = ?',
            [userId]
        );

        if (existingSeller.length > 0) {
            return res.status(400).json({ message: 'You are already a seller' });
        }

        // Insert seller application
        await db.query(
            'INSERT INTO seller_info (user_id, phone, address, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, phone, address, city, state, pincode]
        );

        // Update user role to seller
        await db.query(
            'UPDATE users SET role = ? WHERE id = ?',
            ['seller', userId]
        );

        res.json({ message: 'Seller application submitted successfully' });
    } catch (error) {
        console.error('Error submitting seller application:', error);
        res.status(500).json({ message: 'Error submitting seller application. Please try again.' });
    }
});

// Get seller's books
router.get('/books', auth, async (req, res) => {
    try {
        const [books] = await db.query(
            'SELECT * FROM books WHERE seller_id = ?',
            [req.user.id]
        );
        res.json(books);
    } catch (error) {
        console.error('Error fetching seller books:', error);
        res.status(500).json({ message: 'Error fetching books' });
    }
});

// Get a single book's details
router.get('/books/:id', auth, async (req, res) => {
    try {
        const [books] = await db.query(
            'SELECT * FROM books WHERE id = ? AND seller_id = ?',
            [req.params.id, req.user.id]
        );

        if (books.length === 0) {
            return res.status(404).json({ message: 'Book not found' });
        }

        res.json(books[0]);
    } catch (error) {
        console.error('Error fetching book details:', error);
        res.status(500).json({ message: 'Error fetching book details' });
    }
});

// Add a new book listing
router.post('/books', auth, upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage', maxCount: 1 },
    { name: 'insideImage', maxCount: 1 }
]), async (req, res) => {
    try {
        // Check if seller is approved
        const [sellerInfo] = await db.query(
            'SELECT approved FROM seller_info WHERE user_id = ?',
            [req.user.id]
        );

        if (!sellerInfo || sellerInfo.length === 0 || !sellerInfo[0].approved) {
            return res.status(403).json({ message: 'Please wait for admin approval before listing books' });
        }

        const { title, author, description, price, condition, category } = req.body;
        
        // Process all three images
        const frontImageUrl = req.files.frontImage ? `/uploads/${req.files.frontImage[0].filename}` : null;
        const backImageUrl = req.files.backImage ? `/uploads/${req.files.backImage[0].filename}` : null;
        const insideImageUrl = req.files.insideImage ? `/uploads/${req.files.insideImage[0].filename}` : null;
        
        // For backward compatibility, still use the first image as the main image_url
        const imageUrl = frontImageUrl;
        
        // Validate required fields
        if (!title || !author || !description || !price || !condition || !category) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Insert new book
        const [result] = await db.query(
            'INSERT INTO books (title, author, description, price, `condition`, category, seller_id, image_url, front_image, back_image, inside_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [title, author, description, price, condition, category, req.user.id, imageUrl, frontImageUrl, backImageUrl, insideImageUrl]
        );

        res.status(201).json({
            id: result.insertId,
            message: 'Book listed successfully'
        });
    } catch (error) {
        console.error('Error listing book:', error);
        res.status(500).json({ message: 'Error listing book. Please try again.' });
    }
});

// Update a book listing
router.put('/books/:id', auth, upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage', maxCount: 1 },
    { name: 'insideImage', maxCount: 1 }
]), async (req, res) => {
    try {
        const { title, author, description, price, condition, category } = req.body;
        const bookId = req.params.id;

        // Validate required fields
        if (!title || !author || !description || !price || !condition || !category) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if book belongs to seller
        const [book] = await db.query(
            'SELECT * FROM books WHERE id = ? AND seller_id = ?',
            [bookId, req.user.id]
        );

        if (book.length === 0) {
            return res.status(404).json({ message: 'Book not found' });
        }

        // Process all three images if provided
        const updates = {
            title,
            author,
            description,
            price,
            condition,
            category
        };

        if (req.files.frontImage) {
            updates.front_image = `/uploads/${req.files.frontImage[0].filename}`;
            // For backward compatibility, update the main image_url as well
            updates.image_url = updates.front_image;
        }

        if (req.files.backImage) {
            updates.back_image = `/uploads/${req.files.backImage[0].filename}`;
        }

        if (req.files.insideImage) {
            updates.inside_image = `/uploads/${req.files.insideImage[0].filename}`;
        }

        await db.query(
            'UPDATE books SET ? WHERE id = ?',
            [updates, bookId]
        );

        res.json({ message: 'Book updated successfully' });
    } catch (error) {
        console.error('Error updating book:', error);
        res.status(500).json({ message: 'Error updating book. Please try again.' });
    }
});

// Delete a book listing
router.delete('/books/:id', auth, async (req, res) => {
    try {
        const bookId = req.params.id;

        // Check if book belongs to seller
        const [book] = await db.query(
            'SELECT * FROM books WHERE id = ? AND seller_id = ?',
            [bookId, req.user.id]
        );

        if (book.length === 0) {
            return res.status(404).json({ message: 'Book not found' });
        }

        await db.query('DELETE FROM books WHERE id = ?', [bookId]);
        res.json({ message: 'Book deleted successfully' });
    } catch (error) {
        console.error('Error deleting book:', error);
        res.status(500).json({ message: 'Error deleting book. Please try again.' });
    }
});

// Get seller status
router.get('/status', auth, async (req, res) => {
    try {
        const [sellerInfo] = await db.query(
            'SELECT approved FROM seller_info WHERE user_id = ?',
            [req.user.id]
        );

        if (sellerInfo.length === 0) {
            return res.status(403).json({ message: 'Seller application not found' });
        }

        res.json({ isApproved: sellerInfo[0].approved });
    } catch (error) {
        console.error('Error checking seller status:', error);
        res.status(500).json({ message: 'Error checking seller status' });
    }
});

module.exports = router; 