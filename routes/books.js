const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const pool = require('../config/db');
const { auth, isSeller } = require('../middleware/auth');
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

// @route   GET /api/books
// @desc    Get all books with optional filters
// @access  Public
router.get('/', async (req, res) => {
    try {
        let query = `
            SELECT b.*, u.name as seller_name 
            FROM books b 
            JOIN users u ON b.seller_id = u.id 
            WHERE b.status = 'approved'
        `;
        const params = [];

        // Add search filter (Case-Insensitive)
      if (req.query.search) {
          query += ' AND (LOWER(b.title) LIKE LOWER(?) OR LOWER(b.author) LIKE LOWER(?) OR LOWER(b.description) LIKE LOWER(?))';
          const searchTerm = `%${req.query.search}%`;
          params.push(searchTerm, searchTerm, searchTerm);
      }


        // Add category filter
        if (req.query.category) {
            query += ' AND b.category = ?';
            params.push(req.query.category);
        }

        // Add condition filter
        if (req.query.condition) {
            query += ' AND b.condition = ?';
            params.push(req.query.condition);
        }

        // Add price filter
        if (req.query.price) {
            const [min, max] = req.query.price.split('-');
            if (max === '+') {
                query += ' AND b.price >= ?';
                params.push(parseInt(min));
            } else {
                query += ' AND b.price BETWEEN ? AND ?';
                params.push(parseInt(min), parseInt(max));
            }
        }

        // Add sorting
        if (req.query.sort) {
            switch (req.query.sort) {
                case 'price_low':
                    query += ' ORDER BY b.price ASC';
                    break;
                case 'price_high':
                    query += ' ORDER BY b.price DESC';
                    break;
                case 'newest':
                    query += ' ORDER BY b.created_at DESC';
                    break;
                default:
                    query += ' ORDER BY b.created_at DESC';
            }
        }

        const [books] = await pool.query(query, params);

        // Ensure price is a number
        books.forEach(book => {
        book.price = parseFloat(book.price) || 0;  // Convert to number, default to 0 if null/undefined
        });

        res.json(books);

    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).json({ message: 'Error fetching books' });
    }
});

// @route   GET /api/books/:id
// @desc    Get book by ID
// @access  Public
router.get('/:id', async (req, res) => {
  try {
    const [books] = await pool.query(
      'SELECT b.*, u.name as seller_name FROM books b JOIN users u ON b.seller_id = u.id WHERE b.id = ?',
      [req.params.id]
    );

    if (books.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }

    res.json(books[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/books
// @desc    Create a new book listing
// @access  Private (Sellers only)
router.post('/', [auth, isSeller, [
  body('title').notEmpty().withMessage('Title is required'),
  body('author').notEmpty().withMessage('Author is required'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('condition').isIn(['new', 'like_new', 'good', 'fair', 'poor']).withMessage('Invalid condition'),
  body('category').notEmpty().withMessage('Category is required')
]], upload.single('image'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, author, description, price, condition, category } = req.body;
    const sellerId = req.user.id;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const [result] = await pool.query(
      'INSERT INTO books (title, author, description, price, `condition`, category, seller_id, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [title, author, description, price, condition, category, sellerId, imageUrl]
    );

    const [newBook] = await pool.query('SELECT * FROM books WHERE id = ?', [result.insertId]);
    res.status(201).json(newBook[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/books/:id
// @desc    Update a book listing
// @access  Private (Seller who created the listing)
router.put('/:id', [auth, [
  body('title').optional().notEmpty().withMessage('Title cannot be empty'),
  body('author').optional().notEmpty().withMessage('Author cannot be empty'),
  body('price').optional().isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('condition').optional().isIn(['new', 'like_new', 'good', 'fair', 'poor']).withMessage('Invalid condition'),
  body('category').optional().notEmpty().withMessage('Category cannot be empty')
]], upload.single('image'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Check if book exists and belongs to seller
    const [books] = await pool.query('SELECT * FROM books WHERE id = ?', [req.params.id]);
    if (books.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }

    if (books[0].seller_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update this book' });
    }

    const { title, author, description, price, condition, category, status } = req.body;
    const updates = {};

    // Only include fields that are provided
    if (title) updates.title = title;
    if (author) updates.author = author;
    if (description) updates.description = description;
    if (price) updates.price = price;
    if (condition) updates.condition = condition;
    if (category) updates.category = category;
    if (status && req.user.role === 'admin') updates.status = status;
    if (req.file) updates.image_url = `/uploads/${req.file.filename}`;

    const query = 'UPDATE books SET ? WHERE id = ?';
    await pool.query(query, [updates, req.params.id]);

    const [updatedBook] = await pool.query('SELECT * FROM books WHERE id = ?', [req.params.id]);
    res.json(updatedBook[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   DELETE /api/books/:id
// @desc    Delete a book listing
// @access  Private (Seller who created the listing or Admin)
router.delete('/:id', auth, async (req, res) => {
  try {
    const [books] = await pool.query('SELECT * FROM books WHERE id = ?', [req.params.id]);
    if (books.length === 0) {
      return res.status(404).json({ message: 'Book not found' });
    }

    if (books[0].seller_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to delete this book' });
    }

    await pool.query('DELETE FROM books WHERE id = ?', [req.params.id]);
    res.json({ message: 'Book removed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router; 