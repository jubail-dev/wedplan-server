import { createRemoteJWKSet, jwtVerify } from "jose";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import Stripe from "stripe";

const app = express();

app.use(cors());

const PORT = process.env.PORT || 5000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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

// Customer Authorization Middleware

function verifyCustomer(req, res, next) {
  if (req.user.role !== "customer") {
    return res.status(403).send({
      message: "Access Denied! Customer Only.",
    });
  }

  next();
}

// Vendor Authorization Middleware

function verifyVendor(req, res, next) {
  if (req.user.role !== "vendor") {
    return res.status(403).send({
      message: "Access Denied! Vendor Only.",
    });
  }

  next();
}

// Admin Authorization Middleware
function verifyAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).send({
      success: false,
      message: "Access Denied! Admin Only.",
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


// STRIPE WEBHOOK - VERIFY PAYMENT

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["stripe-signature"];

    if (!signature) {
      return res.status(400).send("Missing Stripe Signature!");
    }

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (error) {
      console.error("Stripe Webhook Signature Error:", error.message);
      return res.status(400).send("Invalid Webhook Signature!");
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        // Verify Payment Information
        const vendorId = session.metadata?.vendorId;

        if (
          session.payment_status !== "paid" ||
          session.mode !== "payment" ||
          session.amount_total !== 9900 ||
          session.currency !== "usd" ||
          session.metadata?.plan !== "premium" ||
          !vendorId ||
          !ObjectId.isValid(vendorId) ||
          session.client_reference_id !== vendorId
        ) {
          return res.status(400).send("Invalid Payment Information!");
        }

        // Find Vendor
        const vendor = await usersCollection.findOne({
          _id: new ObjectId(vendorId),
          role: "vendor",
        });

        if (!vendor) {
          return res.status(404).send("Vendor Not Found!");
        }

        // Save Transaction (Prevent Duplicate Records)
        await transactionsCollection.updateOne(
          { stripeSessionId: session.id },
          {
            $setOnInsert: {
              vendorId,
              plan: "premium",
              amount: session.amount_total / 100,
              currency: session.currency,
              stripeSessionId: session.id,
              stripeSubscriptionId: null,
              status: "paid",
              createdAt: new Date(session.created * 1000),
            },
          },
          { upsert: true },
        );

        // Upgrade Vendor to Premium
        await usersCollection.updateOne(
          {
            _id: new ObjectId(vendorId),
            role: "vendor",
          },
          {
            $set: {
              subscriptionPlan: "premium",
            },
          },
        );
      }

      return res.status(200).send({ received: true });
    } catch (error) {
      console.error("Stripe Webhook Processing Error:", error);
      return res.status(500).send("Webhook Processing Failed!");
    }
  },
);

// Enable JSON Middleware for Other APIs
app.use(express.json());


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


// GET PUBLIC APPROVED AND AVAILABLE SERVICES

app.get("/services", async (req, res) => {
  try {
    // Step 1: Read Search and Filter Parameters
    const search =
      typeof req.query.search === "string"
        ? req.query.search.trim().slice(0, 100)
        : "";

    const category =
      typeof req.query.category === "string"
        ? req.query.category.trim().slice(0, 100)
        : "";

    const location =
      typeof req.query.location === "string"
        ? req.query.location.trim().slice(0, 100)
        : "";

    // Step 2: Escape Regular Expression Characters
    const escapeRegex = (value) =>
      value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    // Step 3: Build Search Query
    const query = {
      status: "Approved",
      isAvailable: true,
    };

    if (search) {
      query.serviceName = {
        $regex: escapeRegex(search),
        $options: "i",
      };
    }

    if (category) {
      query.category = {
        $regex: `^${escapeRegex(category)}$`,
        $options: "i",
      };
    }

    if (location) {
      query.location = {
        $regex: escapeRegex(location),
        $options: "i",
      };
    }

    // Step 4: Fetch Services and Vendor Information
    const services = await servicesCollection
      .aggregate([
        {
          $match: query,
        },

        {
          $sort: {
            createdAt: -1,
          },
        },

        {
          $addFields: {
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

        {
          $unwind: {
            path: "$vendor",
            preserveNullAndEmptyArrays: true,
          },
        },

        {
          $project: {
            vendorObjectId: 0,
            "vendor.role": 0,
          },
        },
      ])
      .toArray();

    // Step 5: Send Response
    return res.status(200).send({
      success: true,
      totalServices: services.length,
      services,
    });
  } catch (error) {
    console.error("Public Services Fetch Error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to Fetch Services!",
    });
  }
});


// GET PUBLIC SERVICE DETAILS BY ID

app.get("/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Validate Service ID
    if (!/^[0-9a-fA-F]{24}$/.test(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid Service ID!",
      });
    }

    // Find Approved and Available Service
    const services = await servicesCollection
      .aggregate([
        {
          $match: {
            _id: new ObjectId(id),
            status: "Approved",
            isAvailable: true,
          },
        },

        // Convert Vendor ID
        {
          $addFields: {
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

        // Get Vendor Information
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

        {
          $unwind: {
            path: "$vendor",
            preserveNullAndEmptyArrays: true,
          },
        },

        {
          $project: {
            vendorObjectId: 0,
            "vendor.role": 0,
          },
        },
      ])
      .toArray();

    // Service Not Found
    if (services.length === 0) {
      return res.status(404).send({
        success: false,
        message: "Service Not Found or Currently Unavailable!",
      });
    }

    // Successful Response
    return res.status(200).send({
      success: true,
      service: services[0],
    });
  } catch (error) {
    console.error("Service Details Fetch Error:", error);

    return res.status(500).send({
      success: false,
      message: "Failed to Fetch Service Details!",
    });
  }
});


// Protected Test Route
app.get("/verify-token", verifyToken, (req, res) => {
  res.send({
    message: "Token Verified Successfully!",
    user: req.user,
  });
});


// Protected Admin Test Route
app.get(
  "/admin/verify",
  verifyToken,
  verifyAdmin,
  (req, res) => {
    res.status(200).send({
      success: true,
      message: "Admin Access Verified Successfully!",
      user: req.user,
    });
  },
);

// ADMIN DASHBOARD STATISTICS API
app.get(
  "/admin/dashboard/stats",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      // Get All Dashboard Statistics
      const [
        totalUsers,
        totalVendors,
        totalCustomers,
        totalServices,
        pendingServices,
        totalTransactions,
      ] = await Promise.all([
        usersCollection.countDocuments(),

        usersCollection.countDocuments({
          role: "vendor",
        }),

        usersCollection.countDocuments({
          role: "customer",
        }),

        servicesCollection.countDocuments(),

        servicesCollection.countDocuments({
          status: "Pending",
        }),

        transactionsCollection.countDocuments(),
      ]);

      // Send Statistics
      return res.status(200).send({
        success: true,
        stats: {
          totalUsers,
          totalVendors,
          totalCustomers,
          totalServices,
          pendingServices,
          totalTransactions,
        },
      });
    } catch (error) {
      console.error("Admin Dashboard Stats Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Admin Dashboard Statistics!",
      });
    }
  },
);

// ADMIN - GET ALL USERS API
app.get(
  "/admin/users",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const search =
        typeof req.query.search === "string"
          ? req.query.search.trim()
          : "";

      const role =
        typeof req.query.role === "string"
          ? req.query.role
          : "";

      const query = {};

      // Search by Name or Email
      if (search) {
        const escapedSearch = search.replace(
          /[.*+?^${}()|[\]\\]/g,
          "\\$&",
        );

        query.$or = [
          { name: { $regex: escapedSearch, $options: "i" } },
          { email: { $regex: escapedSearch, $options: "i" } },
        ];
      }

      // Filter by Role
      if (["admin", "vendor", "customer"].includes(role)) {
        query.role = role;
      }

      const users = await usersCollection
        .find(query, {
          projection: {
            name: 1,
            email: 1,
            image: 1,
            role: 1,
            isBlocked: 1,
            createdAt: 1,
          },
        })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).send({
        success: true,
        totalUsers: users.length,
        users,
      });
    } catch (error) {
      console.error("Admin Get Users Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Users!",
      });
    }
  },
);

// ADMIN - GET SINGLE USER DETAILS API
app.get(
  "/admin/users/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid User ID!",
        });
      }

      const user = await usersCollection.findOne(
        { _id: new ObjectId(id) },
        {
          projection: {
            name: 1,
            email: 1,
            image: 1,
            role: 1,
            isBlocked: 1,
            businessName: 1,
            subscriptionPlan: 1,
            subscriptionExpiresAt: 1,
            createdAt: 1,
          },
        },
      );

      if (!user) {
        return res.status(404).send({
          success: false,
          message: "User Not Found!",
        });
      }

      return res.status(200).send({
        success: true,
        user,
      });
    } catch (error) {
      console.error("Admin Get User Details Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch User Details!",
      });
    }
  },
);

// ADMIN - BLOCK / UNBLOCK USER API
app.patch(
  "/admin/users/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isBlocked } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid User ID!",
        });
      }

      if (typeof isBlocked !== "boolean") {
        return res.status(400).send({
          success: false,
          message: "isBlocked must be a boolean!",
        });
      }

      const targetUser = await usersCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!targetUser) {
        return res.status(404).send({
          success: false,
          message: "User Not Found!",
        });
      }

      // Prevent Admin Self-Blocking
      if (targetUser.role === "admin") {
        return res.status(403).send({
          success: false,
          message: "Admin Accounts Cannot Be Blocked!",
        });
      }

      await usersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            isBlocked,
          },
        },
      );

      return res.status(200).send({
        success: true,
        message: isBlocked
          ? "User Blocked Successfully!"
          : "User Unblocked Successfully!",
      });
    } catch (error) {
      console.error("Admin Update User Status Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Update User Status!",
      });
    }
  },
);


// ADMIN - GET ALL SERVICES API
app.get(
  "/admin/services",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { search, category, location, status, isAvailable } = req.query;

      const filters = {};

      // Search by Service Name or Description
      if (search) {
        const escapedSearch = String(search)
          .trim()
          .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        filters.$or = [
          {
            serviceName: {
              $regex: escapedSearch,
              $options: "i",
            },
          },
          {
            description: {
              $regex: escapedSearch,
              $options: "i",
            },
          },
        ];
      }

      // Filter by Category
      if (category) {
        filters.category = String(category).trim();
      }

      // Filter by Location
      if (location) {
        const escapedLocation = String(location)
          .trim()
          .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        filters.location = {
          $regex: escapedLocation,
          $options: "i",
        };
      }

      // Filter by Approval Status
      const allowedStatuses = ["Pending", "Approved", "Rejected"];

      if (status) {
        if (!allowedStatuses.includes(String(status))) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Status!",
          });
        }

        filters.status = String(status);
      }

      // Filter by Availability
      if (isAvailable !== undefined) {
        if (isAvailable !== "true" && isAvailable !== "false") {
          return res.status(400).send({
            success: false,
            message: "Invalid Availability Value!",
          });
        }

        filters.isAvailable = isAvailable === "true";
      }

      // Fetch Services with Vendor Information
      const services = await servicesCollection
        .aggregate([
          {
            $match: filters,
          },
          {
            $sort: {
              createdAt: -1,
            },
          },
          {
            $lookup: {
              from: "user",
              let: {
                vendorObjectId: {
                  $convert: {
                    input: "$vendorId",
                    to: "objectId",
                    onError: null,
                    onNull: null,
                  },
                },
              },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $eq: ["$_id", "$$vendorObjectId"],
                    },
                  },
                },
                {
                  $project: {
                    name: 1,
                    email: 1,
                    image: 1,
                    businessName: 1,
                    subscriptionPlan: 1,
                  },
                },
              ],
              as: "vendor",
            },
          },
          {
            $unwind: {
              path: "$vendor",
              preserveNullAndEmptyArrays: true,
            },
          },
        ])
        .toArray();

      return res.status(200).send({
        success: true,
        totalServices: services.length,
        services,
      });
    } catch (error) {
      console.error("Admin Get Services Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Services!",
      });
    }
  },
);

// ADMIN - GET SINGLE SERVICE DETAILS API
app.get(
  "/admin/services/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Validate Service ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service ID!",
        });
      }

      const services = await servicesCollection
        .aggregate([
          {
            $match: {
              _id: new ObjectId(id),
            },
          },
          {
            $lookup: {
              from: "user",
              let: {
                vendorObjectId: {
                  $convert: {
                    input: "$vendorId",
                    to: "objectId",
                    onError: null,
                    onNull: null,
                  },
                },
              },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $eq: ["$_id", "$$vendorObjectId"],
                    },
                  },
                },
                {
                  $project: {
                    name: 1,
                    email: 1,
                    image: 1,
                    businessName: 1,
                    role: 1,
                    subscriptionPlan: 1,
                    subscriptionExpiresAt: 1,
                  },
                },
              ],
              as: "vendor",
            },
          },
          {
            $unwind: {
              path: "$vendor",
              preserveNullAndEmptyArrays: true,
            },
          },
        ])
        .toArray();

      // Check if Service Exists
      if (services.length === 0) {
        return res.status(404).send({
          success: false,
          message: "Service Not Found!",
        });
      }

      return res.status(200).send({
        success: true,
        service: services[0],
      });
    } catch (error) {
      console.error("Admin Get Single Service Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Service Details!",
      });
    }
  },
);

// ADMIN - APPROVE / REJECT SERVICE API
app.patch(
  "/admin/services/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      // Step 1: Validate Service ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service ID!",
        });
      }

      // Step 2: Validate Service Status
      const allowedStatuses = ["Approved", "Rejected"];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service Status!",
        });
      }

      // Step 3: Find Service
      const service = await servicesCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!service) {
        return res.status(404).send({
          success: false,
          message: "Service Not Found!",
        });
      }

      // Step 4: Find Vendor
      if (!ObjectId.isValid(service.vendorId)) {
        return res.status(404).send({
          success: false,
          message: "Vendor Not Found!",
        });
      }

      const vendor = await usersCollection.findOne(
        { _id: new ObjectId(service.vendorId) },
        {
          projection: {
            subscriptionPlan: 1,
            role: 1,
          },
        },
      );

      if (!vendor || vendor.role !== "vendor") {
        return res.status(404).send({
          success: false,
          message: "Vendor Not Found!",
        });
      }

      
      // Step 5: Check Free Plan Service Slot Limit
      if (
        status === "Approved" &&
        vendor.subscriptionPlan !== "premium"
      ) {
        const serviceSlotsUsed = await servicesCollection.countDocuments({
          vendorId: service.vendorId,
          status: { $in: ["Pending", "Approved"] },
          isAvailable: { $ne: false },
          _id: { $ne: new ObjectId(id) },
        });

        if (serviceSlotsUsed >= 3) {
          return res.status(403).send({
            success: false,
            message:
              "Free Plan Allows a Maximum of 3 Services. Upgrade to Premium for Unlimited Services.",
          });
        }
      }


      // Step 6: Update Service Status
      const result = await servicesCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        },
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Service Not Found!",
        });
      }

      // Step 7: Send Success Response
      return res.status(200).send({
        success: true,
        message:
          status === "Approved"
            ? "Service Approved Successfully!"
            : "Service Rejected Successfully!",
      });
    } catch (error) {
      console.error("Admin Update Service Status Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Update Service Status!",
      });
    }
  },
);



// ADMIN - UPDATE SERVICE AVAILABILITY API
app.patch(
  "/admin/services/:id/availability",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isAvailable } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service ID!",
        });
      }

      if (typeof isAvailable !== "boolean") {
        return res.status(400).send({
          success: false,
          message: "isAvailable must be a boolean!",
        });
      }

      const service = await servicesCollection.findOne({
        _id: new ObjectId(id),
        status: "Approved",
      });

      if (!service) {
        return res.status(404).send({
          success: false,
          message: "Approved Service Not Found!",
        });
      }

      if (isAvailable) {
        const vendor = await usersCollection.findOne(
          { _id: new ObjectId(service.vendorId) },
          {
            projection: {
              subscriptionPlan: 1,
              role: 1,
            },
          },
        );

        if (!vendor || vendor.role !== "vendor") {
          return res.status(404).send({
            success: false,
            message: "Vendor Not Found!",
          });
        }

        if (vendor.subscriptionPlan !== "premium") {
          const activeServices = await servicesCollection.countDocuments({
            vendorId: service.vendorId,
            status: "Approved",
            isAvailable: { $ne: false },
            _id: { $ne: new ObjectId(id) },
          });

          if (activeServices >= 3) {
            return res.status(403).send({
              success: false,
              message:
                "Free Plan Allows a Maximum of 3 Active Services.",
            });
          }
        }
      }

      await servicesCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            isAvailable,
            updatedAt: new Date(),
          },
        },
      );

      return res.status(200).send({
        success: true,
        message: isAvailable
          ? "Service Activated Successfully!"
          : "Service Deactivated Successfully!",
      });
    } catch (error) {
      console.error("Admin Update Service Availability Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Update Service Availability!",
      });
    }
  },
);



// ADMIN - DELETE SERVICE API
app.delete(
  "/admin/services/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Step 1: Validate Service ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service ID!",
        });
      }

      // Step 2: Check Whether Service Exists
      const service = await servicesCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!service) {
        return res.status(404).send({
          success: false,
          message: "Service Not Found!",
        });
      }

      // Step 3: Delete Service
      const result = await servicesCollection.deleteOne({
        _id: new ObjectId(id),
      });

      if (result.deletedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Service Could Not Be Deleted!",
        });
      }

      // Step 4: Send Success Response
      return res.status(200).send({
        success: true,
        message: "Service Deleted Successfully!",
      });
    } catch (error) {
      console.error("Admin Delete Service Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Delete Service!",
      });
    }
  },
);



// ADMIN - GET ALL TRANSACTIONS API
app.get(
  "/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const transactions = await transactionsCollection
        .aggregate([
          // Step 1: Latest Transactions First
          {
            $sort: {
              createdAt: -1,
            },
          },

          // Step 2: Convert Vendor ID
          {
            $addFields: {
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

          // Step 3: Get Vendor Information
          {
            $lookup: {
              from: "user",
              localField: "vendorObjectId",
              foreignField: "_id",
              pipeline: [
                {
                  $project: {
                    name: 1,
                    email: 1,
                    image: 1,
                    businessName: 1,
                  },
                },
              ],
              as: "vendor",
            },
          },

          // Step 4: Convert Vendor Array to Object
          {
            $unwind: {
              path: "$vendor",
              preserveNullAndEmptyArrays: true,
            },
          },

          // Step 5: Remove Temporary Field
          {
            $project: {
              vendorObjectId: 0,
              stripeSessionId: 0,
              stripeSubscriptionId: 0,
            },
          },
        ])
        .toArray();

      return res.status(200).send({
        success: true,
        totalTransactions: transactions.length,
        transactions,
      });
    } catch (error) {
      console.error("Admin Get Transactions Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Transactions!",
      });
    }
  },
);



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

      // Step 6: Check Service Availability
      if (service.isAvailable !== true) {
        return res.status(403).send({
          message: "This Service Is Currently Unavailable for Booking!",
        });
      }

      // Step 7: Prevent Booking Own Service
      if (service.vendorId?.toString() === req.user.id) {
        return res.status(403).send({
          message: "You Cannot Book Your Own Service!",
        });
      }

      // Step 8: Check Duplicate Active Booking
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

      // Step 9: Prepare Booking Data
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

      // Step 10: Save Booking
      const result = await bookingsCollection.insertOne(bookingData);

      // Step 11: Send Success Response
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


// GET VENDOR'S OWN SERVICES

app.get(
  "/vendor/services",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const vendorId = req.user.id;

      const services = await servicesCollection
        .find({ vendorId })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).send({
        success: true,
        services,
      });
    } catch (error) {
      console.error("Fetch Vendor Services Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Your Services!",
      });
    }
  },
);


 // GET VENDOR'S OWN BOOKING REQUESTS

app.get(
  "/vendor/bookings",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const vendorId = req.user.id;

      const bookings = await bookingsCollection
        .aggregate([
          // Step 1: Get Only This Vendor's Bookings
          {
            $match: {
              vendorId,
            },
          },

          // Step 2: Latest Booking First
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
              customerObjectId: {
                $convert: {
                  input: "$customerId",
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
              localField: "serviceObjectId",
              foreignField: "_id",
              as: "service",
            },
          },
          {
            $unwind: {
              path: "$service",
              preserveNullAndEmptyArrays: true,
            },
          },

          // Step 5: Get Customer Information
          {
            $lookup: {
              from: "user",
              localField: "customerObjectId",
              foreignField: "_id",
              pipeline: [
                {
                  $project: {
                    name: 1,
                    email: 1,
                    image: 1,
                    role: 1,
                  },
                },
              ],
              as: "customer",
            },
          },
          {
            $unwind: {
              path: "$customer",
              preserveNullAndEmptyArrays: true,
            },
          },

          // Step 6: Remove Temporary Fields
          {
            $project: {
              serviceObjectId: 0,
              customerObjectId: 0,
            },
          },
        ])
        .toArray();

      return res.status(200).send({
        success: true,
        bookings,
      });
    } catch (error) {
      console.error("Vendor Bookings Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Fetch Booking Requests!",
      });
    }
  },
);


// UPDATE VENDOR BOOKING REQUEST STATUS

app.patch(
  "/vendor/bookings/:id",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      // Step 1: Validate Booking ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Booking ID!",
        });
      }

      // Step 2: Validate Status
      if (!["Accepted", "Rejected"].includes(status)) {
        return res.status(400).send({
          success: false,
          message: "Status Must Be Accepted or Rejected!",
        });
      }

      // Step 3: Update Only Pending Booking of Logged-in Vendor
      const result = await bookingsCollection.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user.id,
          status: "Pending",
        },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        },
      );

      // Step 4: Check Update Result
      if (result.matchedCount === 0) {
        return res.status(409).send({
          success: false,
          message:
            "Booking Not Found, Unauthorized, or Already Processed!",
        });
      }

      // Step 5: Send Success Response
      return res.status(200).send({
        success: true,
        message: `Booking ${status} Successfully!`,
      });
    } catch (error) {
      console.error("Update Booking Status Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Update Booking Status!",
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
        pendingServices,
        serviceSlotsUsed,
        pendingBookingRequests,
        acceptedBookings,
        user,
      ] = await Promise.all([
        servicesCollection.countDocuments({
          vendorId,
        }),

        // Approved and available services
        servicesCollection.countDocuments({
          vendorId,
          status: "Approved",
          isAvailable: { $ne: false },
        }),

        // Services waiting for admin approval
        servicesCollection.countDocuments({
          vendorId,
          status: "Pending",
        }),

        // Free Plan: Pending + Approved services occupy slots
        servicesCollection.countDocuments({
          vendorId,
          status: { $in: ["Pending", "Approved"] },
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
          pendingServices,
          serviceSlotsUsed,
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



 // CREATE VENDOR SERVICE


app.post(
  "/vendor/services",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const {
        serviceName,
        category,
        description,
        price,
        location,
        imageUrl,
      } = req.body;

      // Step 1: Validate Required Fields
      if (
        typeof serviceName !== "string" ||
        !serviceName.trim() ||
        typeof category !== "string" ||
        !category.trim() ||
        typeof description !== "string" ||
        !description.trim() ||
        typeof location !== "string" ||
        !location.trim() ||
        typeof imageUrl !== "string" ||
        !imageUrl.trim() ||
        typeof price !== "number" ||
        !Number.isFinite(price) ||
        price <= 0
      ) {
        return res.status(400).send({
          success: false,
          message: "Please Provide Valid Service Information!",
        });
      }

      // Step 2: Validate Image URL
      let parsedImageUrl;

      try {
        parsedImageUrl = new URL(imageUrl);
      } catch {
        return res.status(400).send({
          success: false,
          message: "Invalid Service Image URL!",
        });
      }

      if (!["http:", "https:"].includes(parsedImageUrl.protocol)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service Image URL!",
        });
      }

      // Step 3: Get Vendor Subscription Plan
      const vendor = await usersCollection.findOne(
        { _id: new ObjectId(req.user.id) },
        { projection: { subscriptionPlan: 1 } },
      );

      if (!vendor) {
        return res.status(404).send({
          success: false,
          message: "Vendor Account Not Found!",
        });
      }

      const subscriptionPlan = vendor.subscriptionPlan || "free";

      // Step 4: Check Free Plan Service Slot Limit
      if (subscriptionPlan === "free") {
        const serviceSlotsUsed = await servicesCollection.countDocuments({
          vendorId: req.user.id,
          status: { $in: ["Pending", "Approved"] },
          isAvailable: { $ne: false },
        });

        if (serviceSlotsUsed >= 3) {
          return res.status(403).send({
            success: false,
            message:
              "Free Plan Allows a Maximum of 3 Services. Upgrade to Premium for Unlimited Services.",
          });
        }
      }

      // Step 5: Prepare Service Data
      const serviceData = {
        vendorId: req.user.id,
        serviceName: serviceName.trim(),
        category: category.trim(),
        description: description.trim(),
        price,
        location: location.trim(),
        image: imageUrl.trim(),
        images: [imageUrl.trim()],
        status: "Pending",
        isAvailable: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Step 6: Save Service
      const result = await servicesCollection.insertOne(serviceData);

      // Step 7: Send Success Response
      return res.status(201).send({
        success: true,
        message: "Service Submitted Successfully! Waiting for Admin Approval.",
        serviceId: result.insertedId,
      });
    } catch (error) {
      console.error("Create Vendor Service Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Create Service!",
      });
    }
  },
);




// UPDATE VENDOR'S OWN SERVICE

app.patch(
  "/vendor/services/:id",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        serviceName,
        category,
        description,
        price,
        location,
        imageUrl,
        isAvailable,
        status,
      } = req.body;

      // Step 1: Validate Service ID
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid Service ID!",
        });
      }

      // Step 2: Prevent Vendor from Changing Approval Status
      if (status !== undefined) {
        return res.status(403).send({
          success: false,
          message: "You Cannot Change Service Approval Status!",
        });
      }

      // Step 3: Prepare Update Data
      const updateData = {};

      if (serviceName !== undefined) {
        if (typeof serviceName !== "string" || !serviceName.trim()) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Name!",
          });
        }

        updateData.serviceName = serviceName.trim();
      }

      if (category !== undefined) {
        if (typeof category !== "string" || !category.trim()) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Category!",
          });
        }

        updateData.category = category.trim();
      }

      if (description !== undefined) {
        if (typeof description !== "string" || !description.trim()) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Description!",
          });
        }

        updateData.description = description.trim();
      }

      if (price !== undefined) {
        if (
          typeof price !== "number" ||
          !Number.isFinite(price) ||
          price <= 0
        ) {
          return res.status(400).send({
            success: false,
            message: "Price Must Be a Valid Positive Number!",
          });
        }

        updateData.price = price;
      }

      if (location !== undefined) {
        if (typeof location !== "string" || !location.trim()) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Location!",
          });
        }

        updateData.location = location.trim();
      }

      if (imageUrl !== undefined) {
        if (typeof imageUrl !== "string" || !imageUrl.trim()) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Image URL!",
          });
        }

        let parsedImageUrl;

        try {
          parsedImageUrl = new URL(imageUrl);
        } catch {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Image URL!",
          });
        }

        if (!["http:", "https:"].includes(parsedImageUrl.protocol)) {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Image URL!",
          });
        }

        updateData.image = imageUrl.trim();
        updateData.images = [imageUrl.trim()];
      }

      if (isAvailable !== undefined) {
        if (typeof isAvailable !== "boolean") {
          return res.status(400).send({
            success: false,
            message: "Invalid Service Availability!",
          });
        }

        updateData.isAvailable = isAvailable;
      }

      // Step 4: Check Whether There Is Anything to Update
      if (Object.keys(updateData).length === 0) {
        return res.status(400).send({
          success: false,
          message: "Please Provide Information to Update!",
        });
      }

      // Step 5: Update Only the Logged-in Vendor's Service
      updateData.updatedAt = new Date();

      const result = await servicesCollection.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user.id,
        },
        {
          $set: updateData,
        },
      );

      // Step 6: Check Update Result
      if (result.matchedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Service Not Found or Access Denied!",
        });
      }

      // Step 7: Send Success Response
      return res.status(200).send({
        success: true,
        message: "Service Updated Successfully!",
      });
    } catch (error) {
      console.error("Update Vendor Service Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Update Service!",
      });
    }
  },
);



// DELETE VENDOR'S OWN SERVICE
app.delete(
  "/vendor/services/:id",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid service ID",
        });
      }

      const result = await servicesCollection.deleteOne({
        _id: new ObjectId(id),
        vendorId: req.user.id,
      });

      if (result.deletedCount === 0) {
        return res.status(404).send({
          success: false,
          message: "Service not found or unauthorized",
        });
      }

      return res.status(200).send({
        success: true,
        message: "Service deleted successfully",
      });
    } catch (error) {
      console.error("Delete service error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to delete service",
      });
    }
  }
);



// VENDOR - CREATE STRIPE CHECKOUT SESSION

app.post(
  "/vendor/subscription/checkout",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      // Step 1: Find Logged-in Vendor
      const vendor = await usersCollection.findOne(
        { _id: new ObjectId(req.user.id) },
        {
          projection: {
            name: 1,
            email: 1,
            role: 1,
            subscriptionPlan: 1,
          },
        },
      );

      if (!vendor || vendor.role !== "vendor") {
        return res.status(404).send({
          success: false,
          message: "Vendor Account Not Found!",
        });
      }

      // Step 2: Prevent Existing Premium Vendor
      if (vendor.subscriptionPlan === "premium") {
        return res.status(409).send({
          success: false,
          message: "You Already Have Lifetime Premium Access!",
        });
      }

      // Step 3: Create Stripe Checkout Session
      const session = await stripe.checkout.sessions.create({
        mode: "payment",

        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: "WedPlan Premium Lifetime",
                description:
                  "Unlimited Active Services and Premium Vendor Benefits.",
              },
              unit_amount: 9900,
            },
            quantity: 1,
          },
        ],

        client_reference_id: req.user.id,

        customer_email: vendor.email,

        metadata: {
          vendorId: req.user.id,
          plan: "premium",
        },

        success_url: `${process.env.CLIENT_SIDE_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,

        cancel_url: `${process.env.CLIENT_SIDE_URL}/payment/cancel`,
      });

      // Step 4: Send Checkout URL
      return res.status(201).send({
        success: true,
        message: "Checkout Session Created Successfully!",
        url: session.url,
        sessionId: session.id,
      });
    } catch (error) {
      console.error("Stripe Checkout Session Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to Create Checkout Session!",
      });
    }
  },
);



// Start Server
app.listen(PORT, () => {
  console.log(`WedPlan Server is running on port ${PORT}`);
  connectToMongoDB();
});