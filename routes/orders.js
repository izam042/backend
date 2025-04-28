const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const pool = require('../config/db');
const { auth } = require('../middleware/auth');
const Razorpay = require('razorpay');
const crypto = require('crypto');

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: 'YOUR_RAZORPAY_KEY_ID', // Replace with your Razorpay key ID
    key_secret: 'YOUR_RAZORPAY_KEY_SECRET' // Replace with your Razorpay key secret
});

// @route   GET /api/orders
// @desc    Get user's orders (as buyer or seller)
// @access  Private
router.get('/', auth, async (req, res) => {
  try {
    let query = `
      SELECT o.*, 
             b.title as book_title, 
             b.author as book_author,
             b.category as book_category,
             b.condition as book_condition,
             b.image_url as book_image_url,
             b.front_image as book_front_image,
             buyer.name as buyer_name,
             seller.name as seller_name
      FROM orders o
      JOIN books b ON o.book_id = b.id
      JOIN users buyer ON o.buyer_id = buyer.id
      JOIN users seller ON o.seller_id = seller.id
      WHERE o.buyer_id = ? OR o.seller_id = ?
      ORDER BY o.created_at DESC
    `;

    const [orders] = await pool.query(query, [req.user.id, req.user.id]);
    res.json(orders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   GET /api/orders/:id
// @desc    Get order by ID
// @access  Private
router.get('/:id', auth, async (req, res) => {
  try {
    const query = `
      SELECT o.*, 
             b.title as book_title, 
             b.author as book_author,
             buyer.name as buyer_name,
             seller.name as seller_name
      FROM orders o
      JOIN books b ON o.book_id = b.id
      JOIN users buyer ON o.buyer_id = buyer.id
      JOIN users seller ON o.seller_id = seller.id
      WHERE o.id = ?
    `;

    const [orders] = await pool.query(query, [req.params.id]);

    if (orders.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Check if user is buyer or seller
    const order = orders[0];
    if (order.buyer_id !== req.user.id && order.seller_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to view this order' });
    }

    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   POST /api/orders
// @desc    Create a new order
// @access  Private
router.post('/', [auth, [
  body('book_id').isInt().withMessage('Book ID is required')
]], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { book_id } = req.body;

    // Check if book exists and is available
    const [books] = await pool.query('SELECT * FROM books WHERE id = ? AND status = ?', [book_id, 'approved']);
    if (books.length === 0) {
      return res.status(404).json({ message: 'Book not found or not available' });
    }

    const book = books[0];

    // Check if user is not buying their own book
    if (book.seller_id === req.user.id) {
      return res.status(400).json({ message: 'Cannot buy your own book' });
    }

    // Create order
    const [result] = await pool.query(
      'INSERT INTO orders (buyer_id, book_id, seller_id, price) VALUES (?, ?, ?, ?)',
      [req.user.id, book_id, book.seller_id, book.price]
    );

    // Update book status to sold
    await pool.query('UPDATE books SET status = ? WHERE id = ?', ['sold', book_id]);

    const [newOrder] = await pool.query(
      'SELECT * FROM orders WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json(newOrder[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// @route   PUT /api/orders/:id
// @desc    Update order status
// @access  Private
router.put('/:id', [auth, [
  body('status').isIn(['completed', 'cancelled']).withMessage('Invalid status')
]], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { status } = req.body;

    // Check if order exists
    const [orders] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
    if (orders.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }

    const order = orders[0];

    // Check if user is buyer or seller
    if (order.buyer_id !== req.user.id && order.seller_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update this order' });
    }

    // Update order status
    await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);

    // If order is cancelled, make book available again
    if (status === 'cancelled') {
      await pool.query('UPDATE books SET status = ? WHERE id = ?', ['approved', order.book_id]);
    }

    const [updatedOrder] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
    res.json(updatedOrder[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create order and Razorpay order
router.post('/create-order', auth, async (req, res) => {
    try {
        const { items, address, amount } = req.body;
        const userId = req.user.id;
        
        // Create order in database
        const orderQuery = `
            INSERT INTO orders (user_id, total_amount, status, shipping_address)
            VALUES (?, ?, 'pending', ?)
        `;
        
        const [result] = await pool.query(orderQuery, [
            userId,
            amount,
            JSON.stringify(address)
        ]);
        
        const orderId = result.insertId;
        
        // Add order items
        const orderItemsQuery = `
            INSERT INTO order_items (order_id, book_id, quantity, price)
            VALUES ?
        `;
        
        const orderItemsValues = items.map(item => [
            orderId,
            item.id,
            1,
            item.price
        ]);
        
        await pool.query(orderItemsQuery, [orderItemsValues]);
        
        // Create Razorpay order
        const razorpayOrder = await razorpay.orders.create({
            amount: Math.round(amount * 100), // Convert to paise
            currency: 'INR',
            receipt: `order_${orderId}`,
            notes: {
                orderId: orderId.toString()
            }
        });
        
        res.json({
            orderId,
            razorpayOrderId: razorpayOrder.id
        });
        
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Error creating order' });
    }
});

// Verify payment
router.post('/verify-payment', auth, async (req, res) => {
    try {
        const { razorpay_payment_id, razorpay_order_id, razorpay_signature, orderId } = req.body;
        
        // Verify signature
        const body = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', 'YOUR_RAZORPAY_KEY_SECRET') // Replace with your Razorpay key secret
            .update(body.toString())
            .digest('hex');
        
        if (expectedSignature === razorpay_signature) {
            // Update order status
            await pool.query(`
                UPDATE orders
                SET status = 'completed',
                    payment_id = ?,
                    payment_status = 'success'
                WHERE id = ?
            `, [razorpay_payment_id, orderId]);
            
            // Update book status to sold
            const updateBookQuery = `
                UPDATE books b
                JOIN order_items oi ON b.id = oi.book_id
                SET b.status = 'sold'
                WHERE oi.order_id = ?
            `;
            
            await pool.query(updateBookQuery, [orderId]);
            
            res.json({ success: true });
        } else {
            throw new Error('Invalid signature');
        }
        
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).json({ error: 'Error verifying payment' });
    }
});

module.exports = router; 