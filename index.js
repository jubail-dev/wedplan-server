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

function verifyVendor(req, res, next) {
  if (req.user.role !== "vendor") {
    return res.status(403).send({
      message: "Access Denied! Vendor Only.",
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


 // Get Customer Dashboard Statistics
app.get(
  "/customer/dashboard/stats",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const result = await bookingsCollection
        .aggregate([
          {
            $match: {
              customerId: req.user.id,
            },
          },
          {
            $group: {
              _id: null,
              totalBookings: {
                $sum: 1,
              },
              pendingBookings: {
                $sum: {
                  $cond: [{ $eq: ["$status", "Pending"] }, 1, 0],
                },
              },
              acceptedBookings: {
                $sum: {
                  $cond: [{ $eq: ["$status", "Accepted"] }, 1, 0],
                },
              },
              rejectedBookings: {
                $sum: {
                  $cond: [{ $eq: ["$status", "Rejected"] }, 1, 0],
                },
              },
            },
          },
          {
            $project: {
              _id: 0,
            },
          },
        ])
        .toArray();

      return res.status(200).send({
        success: true,
        stats: result[0] || {
          totalBookings: 0,
          pendingBookings: 0,
          acceptedBookings: 0,
          rejectedBookings: 0,
        },
      });
    } catch (error) {
      console.error("Customer Dashboard Stats Error:", error);

      return res.status(500).send({
        message: "Failed to Fetch Dashboard Statistics!",
      });
    }
  },
);


 // Get Customer's Own Bookings
app.get(
  "/customer/bookings",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const bookings = await bookingsCollection
        .aggregate([
          // Step 1: Find Logged-in Customer's Bookings
          {
            $match: {
              customerId: req.user.id,
            },
          },

          // Step 2: Sort Latest Bookings First
          {
            $sort: {
              createdAt: -1,
            },
          },

          // Step 3: Convert IDs to ObjectId
          {
            $addFields: {
              serviceObjectId: {
                $convert: {
                  input: "$serviceId",
                  to: "objectId",
                  onError: null,
                  onNull: null,
                },
              },
              vendorObjectId: {
                $convert: {
                  input: "$vendorId",
                  to: "objectId",
                  onError: null,
                  onNull: null,
                },
              },
            },
          },

          // Step 4: Get Service Information
          {
            $lookup: {
              from: "services",
              let: {
                serviceId: "$serviceObjectId",
              },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $eq: ["$_id", "$$serviceId"],
                    },
                  },
                },
                {
                  $project: {
                    serviceName: 1,
                    category: 1,
                    images: 1,
                    image: 1,
                    price: 1,
                    location: 1,
                  },
                },
              ],
              as: "service",
            },
          },

          // Step 5: Convert Service Array to Object
          {
            $unwind: {
              path: "$service",
              preserveNullAndEmptyArrays: true,
            },
          },

          // Step 6: Get Vendor Information
          {
            $lookup: {
              from: "user",
              let: {
                vendorId: "$vendorObjectId",
              },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $eq: ["$_id", "$$vendorId"],
                    },
                  },
                },
                {
                  $project: {
                    name: 1,
                    image: 1,
                    businessName: 1,
                    role: 1,
                  },
                },
              ],
              as: "vendor",
            },
          },

          // Step 7: Convert Vendor Array to Object
          {
            $unwind: {
              path: "$vendor",
              preserveNullAndEmptyArrays: true,
            },
          },

          // Step 8: Remove Temporary Fields
          {
            $project: {
              serviceObjectId: 0,
              vendorObjectId: 0,
            },
          },
        ])
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
  },
);



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


 // Cancel Customer Booking
app.patch(
  "/customer/bookings/:id/cancel",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      // Step 1: Get Booking ID
      const { id } = req.params;

      // Step 2: Validate Booking ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid Booking ID!",
        });
      }

      // Step 3: Find Customer's Own Booking
      const booking = await bookingsCollection.findOne({
        _id: new ObjectId(id),
        customerId: req.user.id,
      });

      if (!booking) {
        return res.status(404).send({
          message: "Booking Not Found!",
        });
      }

      // Step 4: Check Booking Status
      if (booking.status !== "Pending") {
        return res.status(409).send({
          message: "Only Pending Bookings Can Be Cancelled!",
        });
      }

      // Step 5: Cancel Booking
      const result = await bookingsCollection.updateOne(
        {
          _id: new ObjectId(id),
          customerId: req.user.id,
          status: "Pending",
        },
        {
          $set: {
            status: "Cancelled",
            updatedAt: new Date(),
          },
        },
      );

      // Step 6: Check Update Result
      if (result.modifiedCount === 0) {
        return res.status(409).send({
          message: "Booking Could Not Be Cancelled!",
        });
      }

      // Step 7: Send Success Response
      return res.status(200).send({
        success: true,
        message: "Booking Cancelled Successfully!",
      });
    } catch (error) {
      console.error("Cancel Booking Error:", error);

      return res.status(500).send({
        message: "Failed to Cancel Booking!",
      });
    }
  },
);


// VENDOR DASHBOARD STATS API

app.get(
  "/vendor/dashboard/stats",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const vendorId = req.user.id;

      const [
        totalServices,
        activeServices,
        pendingBookingRequests,
        acceptedBookings,
        user,
      ] = await Promise.all([
        servicesCollection.countDocuments({
          vendorId,
        }),

        servicesCollection.countDocuments({
          vendorId,
          status: "Approved",
          isAvailable: { $ne: false },
        }),

        bookingsCollection.countDocuments({
          vendorId,
          status: "Pending",
        }),

        bookingsCollection.countDocuments({
          vendorId,
          status: "Accepted",
        }),

        usersCollection.findOne(
          { _id: new ObjectId(vendorId) },
          { projection: { subscriptionPlan: 1 } },
        ),
      ]);

      res.send({
        success: true,
        stats: {
          totalServices,
          activeServices,
          pendingBookingRequests,
          acceptedBookings,
          subscriptionPlan: user?.subscriptionPlan || "free",
        },
      });
    } catch (error) {
      console.error("Vendor Dashboard Stats Error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to Load Vendor Dashboard Stats.",
      });
    }
  },
);



// Start Server
app.listen(PORT, () => {
  console.log(`WedPlan Server is running on port ${PORT}`);
  connectToMongoDB();
});
