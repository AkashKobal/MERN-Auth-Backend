import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongoDB.js';
import authRouter from './Routes/authRoutes.js'
import userRouter from './Routes/userRoutes.js'



const app = express();
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || 'localhost';

connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ Credentials: true }));


// API endpoints
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);


app.get('/', (req, res) => {
    res.json(
        {
            message: "Server is running successfully",
            success: true,
            timestamp: new Date().toISOString(),
            status: 200,
            uptime: process.uptime()
        }
    );
});

app.get('/public/health', (req, res) => {
    res.json(
        {
            message: "Server is healthy",
            success: true,
            timestamp: new Date().toISOString(),
            statusCode: 200,
            uptime: process.uptime()
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server is running on http://${HOST}:${PORT}`);
});
