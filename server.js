import express from 'express';
import dotenv from 'dotenv/config';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss-clean';
import compression from 'compression';
import pino from 'pino';
import mongoose from 'mongoose';

import connectDB from './config/mongoDB.js';
import authRouter from './Routes/authRoutes.js';
import userRouter from './Routes/userRoutes.js';
import adminRouter from './Routes/adminRoutes.js';
import emailRouter from './Routes/emailRoutes.js';
import oAuthRoute from './Routes/oAuthRoutes.js';

// ---------------------- App Setup ----------------------
const app = express();
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || 'localhost';
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// ---------------------- MongoDB Connection ----------------------
connectDB().catch(err => {
    logger.error("MongoDB connection failed:", err);
    process.exit(1);
});

// ---------------------- Security Middlewares ----------------------

// Helmet for security headers
app.use(
    helmet({
        crossOriginEmbedderPolicy: true,
        crossOriginResourcePolicy: { policy: "cross-origin" },
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "https:"],
                objectSrc: ["'none'"],
                upgradeInsecureRequests: [],
            },
        },
    })
);

// Sanitize data to prevent NoSQL injection
app.use(mongoSanitize());

// Clean user input to prevent XSS attacks (Sanitizes user input (body, query, params) to remove harmful HTML or script tags.)
{/* <script>alert('hacked')</script> */}
app.use(xss());

// ---------------------- Rate Limiting ----------------------
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 100, // limit each IP
    message: "Too many requests from this IP, please try again later.",
});
app.use(limiter);

// ---------------------- Performance ----------------------
app.use(compression()); // gzip compression for faster responses

// ---------------------- CORS ----------------------
const allowedOrigins = [
    'http://localhost:3000',
    'https://your-production-domain.com'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) callback(null, true);
        else callback(new Error('CORS not allowed'));
    },
    credentials: true,
}));

// ---------------------- Parsers ----------------------
app.use(express.json({ limit: '10kb' })); // limit request body size
app.use(cookieParser());

// ---------------------- Routes ----------------------
app.use('/api/auth', authRouter);
app.use('/api/oauth', oAuthRoute);
app.use('/api/email', emailRouter);
app.use('/api/user', userRouter);
app.use('/api/admin', adminRouter);

// ---------------------- Health Check ----------------------
app.get('/', (req, res) => {
    res.json({
        admin_email: "admin@gmail.com",
        admin_password: "Admin@123",
        message: "Server is running securely",
        success: true,
        timestamp: new Date().toISOString(),
        status: 200,
        uptime: process.uptime(),
    });
});

app.get('/public/health', (req, res) => {
    res.json({
        message: "Server is healthy",
        success: true,
        timestamp: new Date().toISOString(),
        statusCode: 200,
        uptime: process.uptime(),
    });
});

// ---------------------- Error Handling ----------------------
app.use((err, req, res, next) => {
    logger.error(err);
    res.status(err.status || 500).json({
        success: false,
        message: err.message || "Internal server error",
    });
});

// ---------------------- Start Server ----------------------
const server = app.listen(PORT, () => {
    logger.info(`Server running securely at http://${HOST}:${PORT}`);
});

// ---------------------- Graceful Shutdown ----------------------
process.on('SIGINT', () => {
    logger.info('SIGINT received. Shutting down...');
    server.close(() => process.exit(0));
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down...');
    server.close(() => process.exit(0));
});
