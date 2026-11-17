
import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import "dotenv/config";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI);

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
