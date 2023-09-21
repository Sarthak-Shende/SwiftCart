import express from "express";
import * as dotenv from "dotenv";
import cors from "cors";
import connectDB from "./config/connect.js";
import userRouter from "./routes/user.auth.routes.js"
import sellerRouter from "./routes/seller.auth.routes.js";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.use("/api/v1/userAuth",userRouter);
app.use("/api/v1/sellerAuth",sellerRouter);

const startServer = async () => {
    try {
        connectDB(process.env.DB_URI);

        app.listen(3000 , () => console.log("Server started on port http://localhost:3000"));
    } catch (error) {
        console.log(error);
    }
};

startServer();