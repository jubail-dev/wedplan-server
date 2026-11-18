import { createRemoteJWKSet, jwtVerify } from "jose";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
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
  let payload;

  // Step 1: Verify JWT
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({
        message: "Unauthorized Access!",
      });
    }

    const token = authHeader.split(" ")[1];

    const result = await jwtVerify(token, JWKS, {
      issuer: process.env.CLIENT_SIDE_URL,
      audience: process.env.CLIENT_SIDE_URL,
    });

    payload = result.payload;
  } catch (error) {
    return res.status(401).send({
      message: "Invalid or Expired Token!",
    });
  }

  // Step 2: Validate JWT Payload
  if (
    typeof payload.sub !== "string" ||
    payload.id !== payload.sub ||
    typeof payload.role !== "string"
  ) {
    return res.status(401).send({
      message: "Invalid Token Payload!",
    });
  }

  // Step 3: Verify User from MongoDB

  if (!ObjectId.isValid(payload.sub)) {
    return res.status(401).send({
      message: "Invalid User ID!",
    });
  }

  try {
    const user = await usersCollection.findOne(
      { _id: new ObjectId(payload.sub) },
      {
        projection: {
          _id: 1,
          role: 1,
          isBlocked: 1,
        },
      },
    );

    if (!user) {
      return res.status(401).send({
        message: "User Not Found!",
      });
    }

    if (user.isBlocked) {
      return res.status(403).send({
        message: "Your Account Has Been Blocked!",
      });
    }

    if (user.role !== payload.role) {
      return res.status(401).send({
        message: "User Role Changed. Please Sign In Again.",
      });
    }

    req.user = {
      id: user._id.toString(),
      role: user.role,
      isBlocked: user.isBlocked,
    };

    next();
  } catch (error) {
    console.error("User Verification Error:", error);

    return res.status(500).send({
      message: "Internal Server Error!",
    });
  }
}

function verifyCustomer(req, res, next) {
  if (req.user.role !== "customer") {
    return res.status(403).send({
      message: "Access Denied! Customer Only.",
    });
  }

  next();
}

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI);

const db = client.db("wedplan");

const usersCollection = db.collection("user");

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

// Protected Test Route
app.get("/verify-token", verifyToken, (req, res) => {
  res.send({
    message: "Token Verified Successfully!",
    user: req.user,
  });
});

// Get Customer's Own Bookings
app.get("/customer/bookings", verifyToken, verifyCustomer, async (req, res) => {
  try {
    const bookings = await bookingsCollection
      .find({ customerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).send({
      success: true,
      bookings,
    });
  } catch (error) {
    console.error("Customer Bookings Error:", error);

    res.status(500).send({
      message: "Failed to Fetch Bookings!",
    });
  }
});


// Create Customer Booking

// Create Customer Booking
app.post(
  "/customer/bookings",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      // Step 1: Get Request Body
      const { serviceId, eventDate, eventLocation, message } = req.body;

      // Step 2: Validate Required Fields
      if (
        !serviceId ||
        !eventDate ||
        !eventLocation ||
        !ObjectId.isValid(serviceId)
      ) {
        return res.status(400).send({
          message: "Please Provide Valid Booking Information!",
        });
      }

      // Step 3: Validate Event Information
      const parsedEventDate = new Date(eventDate);

      if (
        Number.isNaN(parsedEventDate.getTime()) ||
        typeof eventLocation !== "string" ||
        !eventLocation.trim() ||
        (message !== undefined && typeof message !== "string")
      ) {
        return res.status(400).send({
          message: "Invalid Event Date, Location, or Message!",
        });
      }

      // Step 4: Find Selected Service
      const service = await servicesCollection.findOne({
        _id: new ObjectId(serviceId),
      });

      if (!service) {
        return res.status(404).send({
          message: "Service Not Found!",
        });
      }

      // Step 5: Check Service Approval
      if (service.status !== "Approved") {
        return res.status(403).send({
          message: "This Service Is Not Approved for Booking!",
        });
      }

      // Step 6: Prevent Booking Own Service
      if (service.vendorId?.toString() === req.user.id) {
        return res.status(403).send({
          message: "You Cannot Book Your Own Service!",
        });
      }

      // Step 7: Check Duplicate Active Booking
      const existingBooking = await bookingsCollection.findOne({
        serviceId: service._id.toString(),
        eventDate: parsedEventDate,
        status: {
          $in: ["Pending", "Accepted"],
        },
      });

      if (existingBooking) {
        return res.status(409).send({
          message: "This Service Is Already Booked for This Event Date!",
        });
      }

      // Step 8: Prepare Booking Data
      const bookingData = {
        serviceId: service._id.toString(),
        vendorId: service.vendorId.toString(),
        customerId: req.user.id,
        eventDate: parsedEventDate,
        eventLocation: eventLocation.trim(),
        message: message?.trim() || "",
        status: "Pending",
        createdAt: new Date(),
      };

      // Step 9: Save Booking
      const result = await bookingsCollection.insertOne(bookingData);

      // Step 10: Send Success Response
      return res.status(201).send({
        success: true,
        message: "Booking Request Created Successfully!",
        bookingId: result.insertedId,
      });
    } catch (error) {
      console.error("Create Booking Error:", error);

      return res.status(500).send({
        message: "Failed to Create Booking!",
      });
    }
  },
);

// Start Server
app.listen(PORT, () => {
  console.log(`WedPlan Server is running on port ${PORT}`);
  connectToMongoDB();
});
