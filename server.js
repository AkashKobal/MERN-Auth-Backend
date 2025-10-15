import express from 'express';
import dotenv from 'dotenv/config';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pino from 'pino';
import connectDB from './config/mongoDB.js';
import authRouter from './Routes/authRoutes.js';
import userRouter from './Routes/userRoutes.js';
import adminRouter from './Routes/adminRoutes.js';


const app = express();
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || 'localhost';
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Connect to MongoDB
connectDB().catch(err => {
    logger.error("MongoDB connection failed:", err);
    process.exit(1);
});

// Security middlewares
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: "Too many requests from this IP, please try again later"
});
app.use(limiter);

// CORS
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
}));

// Body parser & cookies
app.use(express.json());
app.use(cookieParser());

// API routes
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.use('/api/admin', adminRouter);

// Health check
app.get('/', (req, res) => {
    res.json({
        admin_email:"admin@gmail.com",
        admin_password:"Admin@123",
        message: "Server is running successfully ",
        success: true,
        timestamp: new Date().toISOString(),
        status: 200,
        uptime: process.uptime()
    });
});

app.get('/public/health', (req, res) => {
    res.json({
        message: "Server is healthy",
        success: true,
        timestamp: new Date().toISOString(),
        statusCode: 200,
        uptime: process.uptime()
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error(err);
    res.status(err.status || 500).json({
        success: false,
        message: err.message || "Internal server error"
    });
});

// Start server
const server = app.listen(PORT, () => {
    logger.info(`Server is running on http://${HOST}:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    logger.info('SIGINT received. Shutting down...');
    server.close(() => process.exit(0));
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down...');
    server.close(() => process.exit(0));
});
