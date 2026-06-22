require('dotenv').config({ override: true });
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const dns = require('dns');

dns.setServers([
  "8.8.8.8",
  "1.1.1.1"
]);
const app = express();
const port = process.env.PORT || 5000;

// ==========================================
// 1. MIDDLEWARE & CORS CONFIGURATION
// ==========================================
app.use(cors({
    origin: [process.env.CLIENT_URL, 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// ==========================================
// 2. MONGODB CONNECTION
// ==========================================
const client = new MongoClient(process.env.MONGODB_URI, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});
const db = client.db('ticketbari');

// ==========================================
// 3. JWT & ROLE VERIFICATION MIDDLEWARE
// ==========================================
const verifyJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send({ message: 'Unauthorized access' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send({ message: 'Unauthorized access' });
        req.decoded = decoded;
        next();
    });
};

const verifyAdmin = async (req, res, next) => {
    const email = req.decoded.email;
    const user = await db.collection('users').findOne({ email });
    if (user?.role !== 'admin') return res.status(403).send({ message: 'Forbidden access' });
    next();
};

const verifyVendor = async (req, res, next) => {
    const email = req.decoded.email;
    const user = await db.collection('users').findOne({ email });
    if (user?.role !== 'vendor' && user?.role !== 'admin') return res.status(403).send({ message: 'Forbidden access' });
    next();
};

// ==========================================
// 4. AUTH & JWT APIs
// ==========================================
// Generate JWT token from email (called after Better Auth login)
app.post('/jwt', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).send({ message: 'Email is required' });
        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.send({ token });
    } catch (error) {
        res.status(500).send({ message: 'Failed to generate token', error: error.message });
    }
});

// Save or update user from Better Auth (upsert)
app.post('/users/save', async (req, res) => {
    try {
        const user = req.body;
        const filter = { email: user.email };
        const updateDoc = {
            $set: {
                name: user.name,
                email: user.email,
                image: user.image || null,
                role: user.role || 'user',
                isFraud: user.isFraud || false,
                updatedAt: new Date()
            },
            $setOnInsert: { createdAt: new Date() }
        };
        const result = await db.collection('users').updateOne(filter, updateDoc, { upsert: true });
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to save user', error: error.message });
    }
});

// Get user by email
app.get('/users/email/:email', verifyJWT, async (req, res) => {
    try {
        const email = req.params.email;
        const user = await db.collection('users').findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.send(user);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch user', error: error.message });
    }
});

// ==========================================
// 5. TICKET APIs
// ==========================================
app.get('/tickets', async (req, res) => {
    try {
        const { search, transportType, sort, page = 1, limit = 6, latest, advertised } = req.query;
        let query = { verificationStatus: 'approved' };

        if (advertised === 'true') query.isAdvertised = true;

        if (search) {
            const [from, to] = search.split('-').map(s => s.trim());
            if (from) query.from = { $regex: from, $options: 'i' };
            if (to) query.to = { $regex: to, $options: 'i' };
        }
        if (transportType) query.transportType = transportType;

        const skip = (page - 1) * limit;
        let sortOption = { departureDate: 1 };
        if (sort === 'lowToHigh') sortOption = { price: 1 };
        if (sort === 'highToLow') sortOption = { price: -1 };
        if (latest === 'true') sortOption = { createdAt: -1 };

        const tickets = await db.collection('tickets').find(query).sort(sortOption).skip(skip).limit(parseInt(limit)).toArray();
        const total = await db.collection('tickets').countDocuments(query);
        res.send({ tickets, total });
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch tickets', error: error.message });
    }
});

app.get('/tickets/admin', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const tickets = await db.collection('tickets').find().toArray();
        res.send(tickets);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch tickets', error: error.message });
    }
});

app.get('/tickets/vendor/:email', verifyJWT, verifyVendor, async (req, res) => {
    try {
        const email = req.params.email;
        const tickets = await db.collection('tickets').find({ vendorEmail: email }).toArray();
        res.send(tickets);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch tickets', error: error.message });
    }
});

app.get('/tickets/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const ticket = await db.collection('tickets').findOne({ _id: new ObjectId(id) });
        if (!ticket) return res.status(404).send({ message: 'Ticket not found' });
        res.send(ticket);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch ticket', error: error.message });
    }
});

app.post('/tickets', verifyJWT, verifyVendor, async (req, res) => {
    try {
        const user = await db.collection('users').findOne({ email: req.decoded.email });
        if (user?.isFraud) return res.status(403).send({ message: 'Fraud vendors cannot add tickets' });

        const ticket = req.body;
        ticket.verificationStatus = 'pending';
        ticket.isAdvertised = false;
        ticket.createdAt = new Date();
        const result = await db.collection('tickets').insertOne(ticket);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to add ticket', error: error.message });
    }
});

app.put('/tickets/:id', verifyJWT, verifyVendor, async (req, res) => {
    try {
        const id = req.params.id;
        const ticket = req.body;
        delete ticket._id;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = { $set: ticket };
        const result = await db.collection('tickets').updateOne(filter, updateDoc);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to update ticket', error: error.message });
    }
});

app.delete('/tickets/:id', verifyJWT, verifyVendor, async (req, res) => {
    try {
        const id = req.params.id;
        const result = await db.collection('tickets').deleteOne({ _id: new ObjectId(id) });
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to delete ticket', error: error.message });
    }
});

app.patch('/tickets/verify/:id', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const { status } = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = { $set: { verificationStatus: status } };
        const result = await db.collection('tickets').updateOne(filter, updateDoc);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to verify ticket', error: error.message });
    }
});



// ==========================================
// 6. USER MANAGEMENT APIs
// ==========================================






app.get('/bookings/vendor/:email', verifyJWT, verifyVendor, async (req, res) => {
    try {
        const email = req.params.email;
        const vendorTickets = await db.collection('tickets').find({ vendorEmail: email }).toArray();
        const ticketIds = vendorTickets.map(t => t._id.toString());

        const bookings = await db.collection('bookings').find({
            $or: [
                { ticketId: { $in: ticketIds } },
                { vendorEmail: email }
            ]
        }).toArray();
        res.send(bookings);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch bookings', error: error.message });
    }
});

app.patch('/bookings/status/:id', verifyJWT, async (req, res) => {
    try {
        const id = req.params.id;
        const { status } = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = { $set: { status } };
        const result = await db.collection('bookings').updateOne(filter, updateDoc);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: 'Failed to update booking', error: error.message });
    }
});

// ==========================================
// 8. PAYMENT & STRIPE APIs
// ==========================================
app.post('/create-payment-intent', verifyJWT, async (req, res) => {
    try {
        const { price } = req.body;
        const amount = parseInt(price * 100);
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: 'usd',
            payment_method_types: ['card']
        });
        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        res.status(500).send({ message: 'Failed to create payment intent', error: error.message });
    }
});

app.post('/save-payment', verifyJWT, async (req, res) => {
    try {
        const payment = req.body;
        payment.paymentDate = new Date();
        const paymentResult = await db.collection('payments').insertOne(payment);

        const bookingFilter = { _id: new ObjectId(payment.bookingId) };
        const bookingUpdate = { $set: { status: 'paid' } };
        await db.collection('bookings').updateOne(bookingFilter, bookingUpdate);

        const booking = await db.collection('bookings').findOne({ _id: new ObjectId(payment.bookingId) });
        if (booking) {
            const ticketFilter = { _id: new ObjectId(booking.ticketId) };
            await db.collection('tickets').updateOne(ticketFilter, {
                $inc: { quantity: -booking.quantity }
            });
        }

        res.send(paymentResult);
    } catch (error) {
        res.status(500).send({ message: 'Failed to save payment', error: error.message });
    }
});

app.get('/transactions/:email', verifyJWT, async (req, res) => {
    try {
        const email = req.params.email;
        const transactions = await db.collection('payments').find({ userEmail: email }).sort({ paymentDate: -1 }).toArray();
        res.send(transactions);
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch transactions', error: error.message });
    }
});

// ==========================================
// 9. STATS APIs
// ==========================================
app.get('/stats/vendor/:email', verifyJWT, verifyVendor, async (req, res) => {
    try {
        const email = req.params.email;
        const tickets = await db.collection('tickets').find({ vendorEmail: email }).toArray();
        const totalAdded = tickets.length;

        const ticketIds = tickets.map(t => t._id.toString());
        const soldBookings = await db.collection('bookings').find({
            ticketId: { $in: ticketIds },
            status: 'paid'
        }).toArray();

        const totalSold = soldBookings.reduce((sum, b) => sum + b.quantity, 0);
        const totalRevenue = soldBookings.reduce((sum, b) => sum + b.totalPrice, 0);

        res.send({ totalAdded, totalSold, totalRevenue });
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch stats', error: error.message });
    }
});

app.get('/stats/admin', verifyJWT, verifyAdmin, async (req, res) => {
    try {
        const totalUsers = await db.collection('users').countDocuments();
        const totalTickets = await db.collection('tickets').countDocuments();
        const totalBookings = await db.collection('bookings').countDocuments();
        const totalRevenue = await db.collection('payments').aggregate([
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]).toArray();

        res.send({
            totalUsers,
            totalTickets,
            totalBookings,
            totalRevenue: totalRevenue[0]?.total || 0
        });
    } catch (error) {
        res.status(500).send({ message: 'Failed to fetch stats', error: error.message });
    }
});

// ==========================================
// 9. ROOT & HEALTH CHECK
// ==========================================
app.get('/', (req, res) => {
    res.send('🎫 TicketBari Server is running...');
});

// ==========================================
// 10. SERVER START
// ==========================================
async function run() {
    try {
        await client.connect();
        console.log("✅ Connected to MongoDB!");

        app.listen(port, () => {
            console.log(`🚀 TicketBari Server is running on port ${port}`);
        });
    } catch (error) {
        console.error("❌ MongoDB Connection Failed:", error);
    }
}
run();