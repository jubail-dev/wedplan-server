import { createRemoteJWKSet, jwtVerify } from "jose";
import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import "dotenv/config";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;


// Better Auth JWKS
const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_SIDE_URL}/api/auth/jwks`),
);

// JWT Verification Middleware
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({
        message: "Unauthorized Access!",
      });
    }

    const token = authHeader.split(" ")[1];

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.CLIENT_SIDE_URL,
      audience: process.env.CLIENT_SIDE_URL,
    });

    req.user = payload;

    next();
  } catch (error) {
    return res.status(401).send({
      message: "Invalid or Expired Token!",
    });
  }
}

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI);

const db = client.db("wedplan");

const servicesCollection = db.collection("services");
const bookingsCollection = db.collection("bookings");
const transactionsCollection = db.collection("transactions");

async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("MongoDB Connected Successfully!");
  } catch (error) {
    console.error("MongoDB Connection Failed:", error);
  }
}

// Home Route
app.get("/", (req, res) => {
  res.send("WedPlan Server is Running!");
});

// Start Server
app.listen(PORT, () => {
  console.log(`WedPlan Server is running on port ${PORT}`);
  connectToMongoDB();
});
