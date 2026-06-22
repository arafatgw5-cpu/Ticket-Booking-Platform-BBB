// Imports
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

// Middleware
app.use(cors({
    origin: [process.env.CLIENT_URL, 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// MongoDB
const client = new MongoClient(process.env.MONGODB_URI, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});
const db = client.db('ticketbari');