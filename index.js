const fs = require('fs').promises;
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const session = require('express-session');
const axios = require('axios');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

// Middleware to parse JSON and URL-encoded form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));

// PostgreSQL configuration for Railway with search path
const pool = new Pool({
    connectionString: 'postgresql://postgres:lNRGchvdLlCbhJfuXCDOSROiSsKhFtmE@yamanote.proxy.rlwy.net:57593/ps',
    ssl: { rejectUnauthorized: false },
    statement_timeout: 30000, // 30 seconds timeout to catch connection issues
    query_timeout: 30000,
    // Set search path to ensure public schema is used
    application_name: 'ps2',
});

// Test database connection and log schema
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error acquiring client from Railway DB', err.stack);
        return;
    }
    console.log('Connected to Railway PostgreSQL database');
    client.query('SHOW search_path', (err, res) => {
        if (err) console.error('Error fetching search path:', err.stack);
        else console.log('Current search path:', res.rows[0].search_path);
        release();
    });
});

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    res.redirect('/authenticate');
};

// Get user country
async function getUserCountry(req) {
    try {
        if (req.session.country) {
            return req.session.country;
        }

        // Extract client IP from X-Forwarded-For header or fallback to connection remote address
        let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (Array.isArray(clientIp)) {
            clientIp = clientIp[0]; // Take the first IP if multiple are present
        }
        // Remove port if included (e.g., "192.168.1.1:port" -> "192.168.1.1")
        clientIp = clientIp.split(':')[0];

        console.log('Detected client IP:', clientIp);

        // Use IP-specific endpoint to get geolocation
        const response = await axios.get(`https://ipapi.co/${clientIp}/json/`, {
            headers: { 'User-Agent': 'PremiumStuff4U/1.0' }
        });
        const country = response.data.country_name;
        req.session.country = country;
        return country;
    } catch (err) {
        console.error('Error fetching geolocation:', err.message);
        return 'United States'; // Default country as fallback
    }
}

// API endpoint to fetch all products with location-based pricing
app.get('/api/products/all', async (req, res) => {
    try {
        const country = await getUserCountry(req);
        console.log('Country detected:', country);
        const priceFieldMap = {
            'United States': { field: 'usa', currency: '$' },
            'Canada': { field: 'canada', currency: 'C$' },
            'United Kingdom': { field: 'uk', currency: '£' },
            'India': { field: 'india', currency: '₹' },
            'New Zealand': { field: 'nz', currency: 'NZ$' },
            'Australia': { field: 'aus', currency: 'A$' }
        };
        const { field, currency } = priceFieldMap[country] || { field: 'usa', currency: '$' };

        const result = await pool.query(
            `SELECT name, prices, usa_price, is_available, category, imagepath, validity 
             FROM products 
             ORDER BY id`
        );

        const products = result.rows.map(product => {
            let display_price = 'N/A';
            let available_validities = product.validity ? product.validity.split('+') : [];
            if (product.prices && product.validity) {
                const firstValidity = available_validities[0];
                display_price = product.prices[firstValidity]?.[field] 
                    ? Number(product.prices[firstValidity][field]).toFixed(2) 
                    : 'N/A';
            } else if (product.usa_price) {
                display_price = Number(product.usa_price).toFixed(2);
            }
            return {
                ...product,
                display_price,
                currency,
                available_validities
            };
        });

        res.setHeader('Content-Type', 'application/json');
        res.json(products);
    } catch (err) {
        console.error('Error fetching all products:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to fetch best-selling products with location-based pricing
app.get('/api/best-sellers', async (req, res) => {
    const bestSellers = [
        'IPTV',
        'Youtube Premium',
        'Netflix',
        'LinkedIn Premium',
        'Spotify Premium',
        'Canva Pro',
        'Instagram followers',
        'Nord VPN'
    ];
    try {
        const country = await getUserCountry(req);
        const priceFieldMap = {
            'United States': { field: 'usa', currency: '$' },
            'Canada': { field: 'canada', currency: 'C$' },
            'United Kingdom': { field: 'uk', currency: '£' },
            'India': { field: 'india', currency: '₹' },
            'New Zealand': { field: 'nz', currency: 'NZ$' },
            'Australia': { field: 'aus', currency: 'A$' }
        };
        const { field, currency } = priceFieldMap[country] || { field: 'usa', currency: '$' };

        const result = await pool.query(
            `SELECT name, prices, usa_price, is_available, category, imagepath, validity 
             FROM products 
             WHERE name = ANY($1::text[]) AND is_available = true 
             ORDER BY array_position($1::text[], name)`,
            [bestSellers]
        );

        const products = result.rows.map(product => {
            let display_price = 'N/A';
            let available_validities = product.validity ? product.validity.split('+') : [];
            if (product.prices && product.validity) {
                const firstValidity = available_validities[0];
                display_price = product.prices[firstValidity]?.[field] 
                    ? Number(product.prices[firstValidity][field]).toFixed(2) 
                    : 'N/A';
            } else if (product.usa_price) {
                display_price = Number(product.usa_price).toFixed(2);
            }
            return {
                ...product,
                display_price,
                currency,
                available_validities
            };
        });

        res.setHeader('Content-Type', 'application/json');
        res.json(products);
    } catch (err) {
        console.error('Error fetching best sellers:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to fetch all products (for admin)
app.get('/api/products', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, is_available, category, imagepath, validity, prices, description FROM products ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching products:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to fetch a single product by name (for admin)
app.get('/api/products/:name', isAuthenticated, async (req, res) => {
    const { name } = req.params;
    try {
        const result = await pool.query(
            'SELECT id, name, is_available, category, imagepath, validity, prices, description FROM products WHERE name = $1',
            [name]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching product:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to update a product (for admin)
app.put('/api/products/:name', isAuthenticated, async (req, res) => {
    const { name } = req.params;
    const { is_available, category, validity, prices, description } = req.body;
    try {
        // Validate prices and validity
        if (prices && validity) {
            const validityOptions = validity.split('+');
            const priceKeys = Object.keys(prices);
            if (!validityOptions.every(opt => priceKeys.includes(opt))) {
                return res.status(400).json({ error: 'Prices keys must match validity options' });
            }
            for (const key of priceKeys) {
                const priceObj = prices[key];
                if (!['usa', 'canada', 'uk', 'india', 'nz', 'aus'].every(region => 
                    priceObj[region] === null || !isNaN(priceObj[region]))) {
                    return res.status(400).json({ error: 'Prices must be valid numbers or null' });
                }
            }
        }

        const result = await pool.query(
            `UPDATE products 
             SET is_available = $1, category = $2, validity = $3, prices = $4,
                 usa_price = NULL, canada_price = NULL, uk_price = NULL,
                 india_price = NULL, nz_price = NULL, aus_price = NULL,
                 description = $5
             WHERE name = $6 
             RETURNING *`,
            [
                is_available === 'true',
                category || null,
                validity || null,
                prices ? JSON.stringify(prices) : null,
                description || null,
                name
            ]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating product:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Endpoint to serve authenticate.html
app.get('/authenticate', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'authenticate.html'));
});

// Endpoint to handle login form submission
app.post('/authenticate', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 AND password = $2',
            [username, password]
        );
        if (result.rows.length === 0) {
            return res.redirect('/authenticate?error=invalid');
        }
        req.session.user = { username: result.rows[0].username };
        res.redirect('/admin');
    } catch (err) {
        console.error('Error during authentication:', err.stack);
        res.redirect('/authenticate?error=server');
    }
});

// Endpoint to serve admin.html (protected)
app.get('/admin', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/links', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'links.html'));
});

// Endpoint to serve shop.html
app.get('/shop', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'shop.html'));
});

// Endpoint to serve home.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/iptv', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'iptv.html'));
});
app.get('/career-growth', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'career-growth.html'));
});
app.get('/streaming', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'streaming.html'));
});
app.get('/social-media', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'social-media.html'));
});
app.get('/designing', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'designing.html'));
});
app.get('/other-utilities', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'other-utilities.html'));
});
app.get('/refer-friends', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'referfriends.html'));
});
app.get('/faq', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'faq.html'));
});
app.get('/contact-us', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'contact-us.html'));
});
app.get('/our-story', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'our-story.html'));
});
app.get('/cart', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cart.html'));
});
app.get('/product/:productName', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'product.html'));
});

// Clear session for testing
app.get('/clear-session', (req, res) => {
    req.session.destroy();
    res.send('Session cleared');
});


// API endpoint to get session ID
app.get('/api/session-id', (req, res) => {
    // If session ID doesn't exist in the session, create one
    if (!req.session.sessionId) {
        req.session.sessionId = 'session-' + require('crypto').randomBytes(16).toString('hex');
    }
    
    // Set the same session ID in a cookie for client-side access
    res.cookie('sessionId', req.session.sessionId, {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true
    });
    
    res.json({ 
        sessionId: req.session.sessionId,
        sessionIdFromSession: req.sessionID // For debugging
    });
});

// API endpoint to fetch all links (for admin)
app.get('/api/links', async (req, res) => { // Removed isAuthenticated
    try {
        const result = await pool.query(
            'SELECT id, name, url FROM links ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching links:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to update a link (for admin)
app.put('/api/links/:name', isAuthenticated, async (req, res) => {
    const { name } = req.params;
    const { url } = req.body;
    try {
        // Validate URL
        if (!url || !url.match(/^https?:\/\/[^\s/$.?#].[^\s]*$/i)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        const result = await pool.query(
            `UPDATE links 
             SET url = $1
             WHERE name = $2 
             RETURNING *`,
            [url, name]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Link not found' });
        }
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating link:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});
// API endpoint to fetch all community links (for admin)
app.get('/api/communitylinks', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, url FROM communitylinks ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching community links:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to update a community link (for admin)
app.put('/api/communitylinks/:name', isAuthenticated, async (req, res) => {
    const { name } = req.params;
    const { url } = req.body;
    try {
        // Validate URL
        if (!url || !url.match(/^https?:\/\/[^\s/$.?#].[^\s]*$/i)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        const result = await pool.query(
            `UPDATE communitylinks 
             SET url = $1
             WHERE name = $2 
             RETURNING *`,
            [url, name]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Community link not found' });
        }
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating community link:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});
// API endpoint to fetch all community links (public)
app.get('/api/communitylinks/public', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, url FROM communitylinks ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching community links:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});
app.get('/api/freetriallinks/public', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, url FROM freetriallinks ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching free trial links:', err.stack);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to fetch all free trial links (for admin)
app.get('/api/freetriallinks', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, url FROM freetriallinks ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching free trial links:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to update a free trial link (for admin)
app.put('/api/freetriallinks/:name', isAuthenticated, async (req, res) => {
    const { name } = req.params;
    const { url } = req.body;
    try {
        if (!url || !url.match(/^https?:\/\/[^\s/$.?#].[^\s]*$/i)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }
        const result = await pool.query(
            `UPDATE freetriallinks 
             SET url = $1
             WHERE name = $2 
             RETURNING *`,
            [url, name]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Free trial link not found' });
        }
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating free trial link:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// API endpoint to fetch all free trial links (public)
app.get('/api/freetriallinks/public', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, url FROM freetriallinks ORDER BY id'
        );
        res.setHeader('Content-Type', 'application/json');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching free trial links:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});
app.get('/api/testimonials', async (req, res) => {
    try {
        const ssDir = path.join(__dirname, 'public', 'ss');
        const files = await fs.readdir(ssDir);
        const imageFiles = files
            .filter(file => /\.(jpg|jpeg|png|gif)$/i.test(file))
            .map(file => `ss/${file}`);
        res.setHeader('Content-Type', 'application/json');
        res.json(imageFiles);
    } catch (err) {
        console.error('Error fetching testimonial images:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});
// Middleware to get consistent session ID
const getSessionId = (req) => {
    // Priority: session > cookie > newly generated
    if (req.session.sessionId) {
        return req.session.sessionId;
    }
    
    // Check cookies if session doesn't have it
    if (req.cookies.sessionId) {
        req.session.sessionId = req.cookies.sessionId;
        return req.session.sessionId;
    }
    
    // Generate new session ID if none exists
    req.session.sessionId = 'session-' + require('crypto').randomBytes(16).toString('hex');
    return req.session.sessionId;
};
// Update the /api/cart endpoint to check for existing items
app.post('/api/cart', async (req, res) => {
    try {
        const { sessionId, productName, validity, quantity, price, currency } = req.body;
        
        // Validate input
        if (!sessionId || !productName || !validity || !quantity || !price || !currency) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Check if the product exists
        const productCheck = await pool.query(
            'SELECT id FROM products WHERE name = $1',
            [productName]
        );
        
        if (productCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Check if the same product with same validity already exists in cart
        const existingItem = await pool.query(
            `SELECT id FROM cart 
             WHERE session_id = $1 
             AND product_name = $2 
             AND validity = $3
             AND added_at > NOW() - INTERVAL '5 minutes'`, // Only check recent additions
            [sessionId, productName, validity]
        );

        if (existingItem.rows.length > 0) {
            // Update quantity if item exists
            const updateResult = await pool.query(
                `UPDATE cart 
                 SET quantity = quantity + $1,
                     price = $2
                 WHERE id = $3
                 RETURNING *`,
                [quantity, price, existingItem.rows[0].id]
            );
            return res.json(updateResult.rows[0]);
        }

        // Insert new item if it doesn't exist
        const result = await pool.query(
            `INSERT INTO cart (session_id, product_id, product_name, validity, quantity, price, currency, added_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
             RETURNING *`,
            [
                sessionId,
                productCheck.rows[0].id,
                productName,
                validity,
                quantity,
                price,
                currency
            ]
        );

        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error adding to cart:', err.stack);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Updated /api/cart GET endpoint
app.get('/api/cart', async (req, res) => {
    try {
        const sessionId = req.session.sessionId || req.cookies.sessionId;
        
        if (!sessionId) {
            return res.status(400).json({
                success: false,
                error: 'Session ID required'
            });
        }

        console.log('Fetching cart for session:', sessionId);
        
        const result = await pool.query(
            `SELECT c.id, c.product_name, c.validity, c.quantity, c.price, c.currency, 
                    p.imagepath, p.validity as available_validities, p.prices
             FROM cart c
             LEFT JOIN products p ON c.product_name = p.name
             WHERE c.session_id = $1
             ORDER BY c.added_at DESC`,
            [sessionId]
        );

        console.log('Number of cart items found:', result.rows.length);
        
        const cartItems = result.rows.map(item => {
            let prices = null;
            try {
                prices = item.prices ? JSON.parse(item.prices) : null;
            } catch (parseErr) {
                console.warn(`Failed to parse prices for item ${item.id}:`, item.prices, parseErr.message);
                prices = null; // Fallback to null if parsing fails
            }
            return {
                ...item,
                available_validities: item.available_validities ? item.available_validities.split('+') : [],
                prices: prices
            };
        });

        res.json({
            success: true,
            sessionId: sessionId,
            items: cartItems
        });
    } catch (err) {
        console.error('Error fetching cart items:', err.stack);
        res.status(500).json({ 
            success: false,
            error: 'Server error',
            details: process.env.NODE_ENV === 'development' ? err.message : null
        });
    }
});

// ... (previous code remains unchanged until /api/cart endpoints)

// API endpoint to update cart item quantity
app.put('/api/cart/:itemId', async (req, res) => {
    try {
        const sessionId = getSessionId(req);
        const { itemId } = req.params;
        const { quantity } = req.body;

        if (!quantity || isNaN(quantity)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid quantity' 
            });
        }

        // Verify the item belongs to this session
        const verifyResult = await pool.query(
            'SELECT id FROM cart WHERE id = $1 AND session_id = $2',
            [itemId, sessionId]
        );

        if (verifyResult.rows.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Cart item not found or does not belong to this session' 
            });
        }

        const result = await pool.query(
            `UPDATE cart 
             SET quantity = $1 
             WHERE id = $2
             RETURNING *`,
            [quantity, itemId]
        );

        res.json({
            success: true,
            item: result.rows[0]
        });
    } catch (err) {
        console.error('Error updating cart item:', err.stack);
        res.status(500).json({ 
            success: false,
            error: 'Server error', 
            details: err.message 
        });
    }
});

// API endpoint to remove item from cart
app.delete('/api/cart/:itemId', async (req, res) => {
    try {
        const sessionId = getSessionId(req);
        const { itemId } = req.params;

        const verifyResult = await pool.query(
            'SELECT id FROM cart WHERE id = $1 AND session_id = $2',
            [itemId, sessionId]
        );

        if (verifyResult.rows.length === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Cart item not found or does not belong to this session' 
            });
        }

        const result = await pool.query(
            'DELETE FROM cart WHERE id = $1 RETURNING *',
            [itemId]
        );

        res.json({ 
            success: true,
            item: result.rows[0]
        });
    } catch (err) {
        console.error('Error removing cart item:', err.stack);
        res.status(500).json({ 
            success: false,
            error: 'Server error', 
            details: err.message 
        });
    }
});

// API endpoint to create a new order
// API endpoint to create a new order
app.post('/api/orders', async (req, res) => {
    const client = await pool.connect(); // Use a transaction client
    try {
        await client.query('BEGIN');

        const { session_id, name, email, phone, total, currency, items } = req.body;

        if (!session_id || !name || !email || !phone || !total || !currency || !items || !Array.isArray(items)) {
            throw new Error('Missing required fields');
        }

        // Insert the order
        const orderResult = await client.query(
            `INSERT INTO orders (session_id, name, email, phone, total, currency, items, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
             RETURNING id`,
            [session_id, name, email, phone, total, currency, JSON.stringify(items)]
        );

        const orderId = orderResult.rows[0].id;

        // Delete cart items for the session_id
        await client.query(
            'DELETE FROM cart WHERE session_id = $1',
            [session_id]
        );

        await client.query('COMMIT');

        res.json({ success: true, orderId });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error creating order:', err.stack);
        res.status(500).json({ success: false, error: 'Server error', details: process.env.NODE_ENV === 'development' ? err.message : null });
    } finally {
        client.release();
    }
});
// Enhanced search endpoint with jsonb prices and validity support
// In your index.js
app.get('/api/products/search', async (req, res) => {
    try {
        const searchTerm = req.query.q;
        
        if (!searchTerm || searchTerm.trim() === '') {
            return res.status(400).json({ 
                success: false,
                error: 'Search term is required'
            });
        }

        const country = await getUserCountry(req);
        const { field, currency } = getPriceField(country);

        const { rows } = await pool.query(`
            SELECT 
                id, name, prices, is_available, category, 
                imagepath, validity, description
            FROM products
            WHERE (
                to_tsvector('english', name) @@ to_tsquery('english', $1) OR
                to_tsvector('english', category) @@ to_tsquery('english', $1)
            ) 
            AND is_available = true
            ORDER BY 
                ts_rank(to_tsvector('english', name), to_tsquery('english', $1)) DESC
            LIMIT 10
        `, [searchTerm.split(' ').filter(Boolean).join(' & ')]);

        const products = rows.map(product => ({
            ...product,
            display_price: calculateDisplayPrice(product, field),
            currency,
            available_validities: product.validity ? product.validity.split('+') : []
        }));

        res.json({ 
            success: true,
            data: products
        });

    } catch (err) {
        console.error('Search endpoint error:', err);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
});

function calculateDisplayPrice(product, field) {
    if (!product.prices || !product.validity) return 'N/A';
    const firstValidity = product.validity.split('+')[0];
    const priceValue = product.prices[firstValidity]?.[field];
    return priceValue ? Number(priceValue).toFixed(2) : 'N/A';
}

function getPriceField(country) {
    const priceFieldMap = {
        'United States': { field: 'usa', currency: '$' },
        'Canada': { field: 'canada', currency: 'C$' },
        'United Kingdom': { field: 'uk', currency: '£' },
        'India': { field: 'india', currency: '₹' },
        'New Zealand': { field: 'nz', currency: 'NZ$' },
        'Australia': { field: 'aus', currency: 'A$' }
    };
    return priceFieldMap[country] || { field: 'usa', currency: '$' };
}

// API endpoint to fetch a single product by name (public)
app.get('/api/product/:name', async (req, res) => {
    const { name } = req.params;
    try {
        const country = await getUserCountry(req);
        const priceFieldMap = {
            'United States': { field: 'usa', currency: '$' },
            'Canada': { field: 'canada', currency: 'C$' },
            'United Kingdom': { field: 'uk', currency: '£' },
            'India': { field: 'india', currency: '₹' },
            'New Zealand': { field: 'nz', currency: 'NZ$' },
            'Australia': { field: 'aus', currency: 'A$' }
        };
        const { field, currency } = priceFieldMap[country] || { field: 'usa', currency: '$' };

        const result = await pool.query(
            `SELECT name, prices, usa_price, is_available, category, imagepath, validity, description
             FROM products 
             WHERE name = $1`,
            [name]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const product = result.rows[0];
        let display_price = 'N/A';
        let available_validities = product.validity ? product.validity.split('+') : [];
        if (product.prices && product.validity) {
            const firstValidity = available_validities[0];
            display_price = product.prices[firstValidity]?.[field] 
                ? Number(product.prices[firstValidity][field]).toFixed(2) 
                : 'N/A';
        } else if (product.usa_price) {
            display_price = Number(product.usa_price).toFixed(2);
        }

        res.setHeader('Content-Type', 'application/json');
        res.json({
            ...product,
            display_price,
            currency,
            available_validities
        });
    } catch (err) {
        console.error('Error fetching product:', err.stack);
        res.setHeader('Content-Type', 'application/json');
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});
// Serve static files after API routes to avoid interference
app.use(express.static(path.join(__dirname, 'public')));


// Catch-all route for undefined routes
app.use((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});