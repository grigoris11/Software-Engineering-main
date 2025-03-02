// Entry point of the application
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Database Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Could not connect to MongoDB:", err));

// Models
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ["USER", "ADMIN", "ARTIST", "STAFF", "ORGANIZER"],
    required: true,
  },
  accountStatus: {
    type: String,
    enum: ["ACTIVE", "INACTIVE"],
    default: "ACTIVE",
  },
});

UserSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model("User", UserSchema);

const FestivalSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  description: String,
  dates: { start: Date, end: Date },
  venue: String,
  organizers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  state: {
    type: String,
    enum: [
      "CREATED",
      "SUBMISSION",
      "ASSIGNMENT",
      "REVIEW",
      "SCHEDULING",
      "FINAL_SUBMISSION",
      "DECISION",
      "ANNOUNCED",
    ],
    default: "CREATED",
  },
});

const Festival = mongoose.model("Festival", FestivalSchema);

const PerformanceSchema = new mongoose.Schema({
  festival: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Festival",
    required: true,
  },
  name: { type: String, required: true },
  description: String,
  genre: String,
  duration: Number,
  bandMembers: [String],
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  state: {
    type: String,
    enum: [
      "CREATED",
      "SUBMITTED",
      "REVIEWED",
      "APPROVED",
      "REJECTED",
      "SCHEDULED",
      "FINAL_SUBMITTED",
    ],
    default: "CREATED",
  },
  staffAssigned: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  review: {
    score: Number,
    comments: String,
  },
  setlist: [String], // Προστέθηκε για τη λίστα τραγουδιών
  preferredRehearsalSlots: [String], // Προστέθηκε για τις ώρες πρόβας
  preferredPerformanceSlots: [String], // Προστέθηκε για τις ώρες εμφάνισης
  createdAt: { type: Date, default: Date.now },
});

const Performance = mongoose.model("Performance", PerformanceSchema);

// Authentication Middleware
// Authentication Middleware with Advanced Token Validation
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Access denied. No token provided.");

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Find user in the database
    const user = await User.findById(decoded._id);
    if (!user) {
      return res.status(403).send("Invalid token. User not found.");
    }

    // Check if the account is active
    if (user.accountStatus === "INACTIVE") {
      return res
        .status(403)
        .send("Account is inactive. Contact an administrator.");
    }

    // Check if the token belongs to the requesting user
    if (req.user && req.user._id !== decoded._id) {
      // Deactivate both accounts
      await User.findByIdAndUpdate(decoded._id, { accountStatus: "INACTIVE" });
      await User.findByIdAndUpdate(req.user._id, { accountStatus: "INACTIVE" });

      return res
        .status(403)
        .send("Unauthorized token usage. Both accounts deactivated.");
    }

    // Attach user data to request object
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).send("Token has expired. Please login again.");
    } else {
      return res.status(400).send("Invalid token.");
    }
  }
};

// Helper function for role-based access
const authorize = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).send("Access denied.");
  }
  next();
};

// Routes
// User Registration with Password and Username Validation and Double Input Check
app.post("/users/register", async (req, res) => {
  try {
    const { username, password, confirmPassword, role } = req.body;

    /*
    // Username validation
    const usernameRegex = /^[a-zA-Z][a-zA-Z0-9_]{4,}$/;
    if (!usernameRegex.test(username)) {
      return res
        .status(400)
        .send(
          "Username must start with a letter and be at least 5 characters long, containing only letters, numbers, or underscores."
        );
    }

    // Password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    if (!passwordRegex.test(password)) {
      return res
        .status(400)
        .send(
          "Password must be at least 8 characters long, include at least one uppercase letter, one lowercase letter, one digit, and one special character."
        );
    }

    // Confirm password check
    if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match.");
    }
  */

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).send("Username is already taken.");
    }
  

    // Create and save new user
    const user = new User({ username, password, role });
    await user.save();
    res.status(201).send("User registered successfully.");
  } catch (error) {
    res.status(400).send(error.message || "An error occurred during registration.");
  }
});


// Update User Information
app.put("/users/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Find user by ID
    const user = await User.findById(id);
    if (!user) return res.status(404).send("User not found.");

    // Check if the authenticated user is the owner or an admin
    if (req.user._id !== id && req.user.role !== "ADMIN") {
      return res.status(403).send("Access denied.");
    }

    // Prevent updating password
    if (updates.password) {
      return res
        .status(400)
        .send("Password cannot be updated using this endpoint.");
    }

    // Check if username is being changed
    const isUsernameChanged = updates.username && updates.username !== user.username;

    // Update user details
    Object.assign(user, updates);
    await user.save();

    // Invalidate token if username changes
    if (isUsernameChanged) {
      return res
        .status(200)
        .send("Username updated. Please log in again with the new username.");
    }

    res.status(200).send("User information updated successfully.");
  } catch (error) {
    res.status(400).send(error.message);
  }
});


// Change User Password
app.post("/users/change-password", authenticate, async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    // Validate inputs
    if (!oldPassword || !newPassword || !confirmPassword) {
      return res
        .status(400)
        .send("Old password, new password, and confirmation are required.");
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).send("Passwords do not match.");
    }

    // Find the user
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).send("User not found.");

    // Check old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      // Track failed attempts
      user.failedPasswordAttempts = (user.failedPasswordAttempts || 0) + 1;
      await user.save();

      // Deactivate account after 3 failed attempts
      if (user.failedPasswordAttempts >= 3) {
        user.accountStatus = "INACTIVE";
        await user.save();
        return res
          .status(403)
          .send("Account deactivated due to multiple failed attempts.");
      }

      return res.status(400).send("Old password is incorrect.");
    }

    // Reset failed attempts
    user.failedPasswordAttempts = 0;

    // Update password
    user.password = newPassword;
    await user.save();

    res
      .status(200)
      .send("Password updated successfully. Please log in again.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});




/* User Login Old
app.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send("Invalid username or password.");
    }
    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.send({ token });
  } catch (error) {
    res.status(400).send(error);
  }
});*/

// User Login
app.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Εύρεση χρήστη με το username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).send("Invalid username or password.");
    }

    // Έλεγχος κατάστασης λογαριασμού
    if (user.accountStatus === "INACTIVE") {
      return res
        .status(403)
        .send("Account is inactive. Contact an administrator.");
    }

    // Επαλήθευση κωδικού
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid username or password.");
    }

    // Δημιουργία JWT token
    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.send({ token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Change Password
app.post("/users/change-password", authenticate, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Επαλήθευση αν παρέχονται τα πεδία
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .send("Old password and new password are required.");
    }

    // Εύρεση χρήστη από το token
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).send("User not found.");
    }

    // Επαλήθευση παλιού κωδικού
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).send("Old password is incorrect.");
    }

    // Αλλαγή κωδικού
    user.password = newPassword;
    await user.save();

    res.status(200).send("Password updated successfully.");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Change User Account Status
app.post(
  "/users/:id/status",
  authenticate,
  authorize(["ADMIN"]),
  async (req, res) => {
    try {
      const { status } = req.body;

      // Επαλήθευση αν παρέχεται έγκυρη κατάσταση
      if (!["ACTIVE", "INACTIVE"].includes(status)) {
        return res
          .status(400)
          .send("Invalid status. Use 'ACTIVE' or 'INACTIVE'.");
      }

      // Εύρεση του χρήστη από το ID
      const user = await User.findById(req.params.id);
      if (!user) {
        return res.status(404).send("User not found.");
      }

      // Ενημέρωση της κατάστασης του λογαριασμού
      user.accountStatus = status;
      await user.save();

      res.status(200).send(`User status updated to ${status}.`);
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);

// Delete User
app.delete(
  "/users/:id",
  authenticate,
  authorize(["ADMIN"]),
  async (req, res) => {
    try {
      const user = await User.findByIdAndDelete(req.params.id);
      if (!user) {
        return res.status(404).send("User not found.");
      }
      res.status(200).send("User deleted successfully.");
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);

// Create Festival
app.post(
  "/festivals",
  authenticate,
  authorize(["ADMIN", "ORGANIZER"]),
  async (req, res) => {
    try {
      const { name, description, dates, venue } = req.body;

      // Ensure unique festival name
      const existingFestival = await Festival.findOne({ name });
      if (existingFestival) {
        return res.status(400).send("Festival name must be unique.");
      }

      const festival = new Festival({
        name,
        description,
        dates,
        venue,
        organizers: [req.user._id],
      });

      await festival.save();
      res.status(201).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);
// Update Festival Details
app.put("/festivals/:id", authenticate, authorize(["ORGANIZER"]), async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Find the festival by ID
    const festival = await Festival.findById(id);
    if (!festival) {
      return res.status(404).send("Festival not found.");
    }

    // Prevent updates if the festival is ANNOUNCED
    if (festival.state === "ANNOUNCED") {
      return res.status(400).send("No updates allowed. Festival is announced.");
    }

    // Update allowed fields
    const allowedUpdates = ["name", "description", "dates", "venue"];
    Object.keys(updates).forEach((key) => {
      if (allowedUpdates.includes(key)) {
        festival[key] = updates[key];
      }
    });

    // Save the updated festival
    await festival.save();

    res.status(200).send(festival);
  } catch (error) {
    res.status(400).send(error.message);
  }
});



// Start Final Submission Phase
app.post(
  "/festivals/:id/start-final-submission",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);

      if (!festival) {
        return res.status(404).send("Festival not found.");
      }

      // Check if the festival is in the SCHEDULING state
      if (festival.state !== "SCHEDULING") {
        return res
          .status(400)
          .send(
            "Festival must be in SCHEDULING state to start the final submission phase."
          );
      }

      // Update the festival state to FINAL_SUBMISSION
      festival.state = "FINAL_SUBMISSION";
      await festival.save();

      res.status(200).send({
        message: "Festival state updated to FINAL_SUBMISSION.",
        festival,
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);


// Start Decision Phase
app.post(
  "/festivals/:id/start-decision",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);

      if (!festival) {
        return res.status(404).send("Festival not found.");
      }

      // Check if the festival is in the FINAL_SUBMISSION state
      if (festival.state !== "FINAL_SUBMISSION") {
        return res
          .status(400)
          .send(
            "Festival must be in FINAL_SUBMISSION state to start the decision phase."
          );
      }

      // Fetch all approved performances for the festival
      const performances = await Performance.find({
        festival: festival._id,
        state: "APPROVED",
      });

      // Automatically reject approved performances that are not finally submitted
      const rejectedPerformances = [];
      for (const performance of performances) {
        if (performance.state !== "FINAL_SUBMITTED") {
          performance.state = "REJECTED";
          await performance.save();
          rejectedPerformances.push(performance.name);
        }
      }

      // Update the festival state to DECISION
      festival.state = "DECISION";
      await festival.save();

      res.status(200).send({
        message: "Festival state updated to DECISION.",
        rejectedPerformances,
        festival,
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);



// Announce Festival
app.post(
  "/festivals/:id/announce",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);

      if (!festival) {
        return res.status(404).send("Festival not found.");
      }

      // Check if the festival is in the DECISION state
      if (festival.state !== "DECISION") {
        return res
          .status(400)
          .send(
            "Festival must be in DECISION state to be announced."
          );
      }

      // Update the festival state to ANNOUNCED
      festival.state = "ANNOUNCED";
      await festival.save();

      res.status(200).send({
        message: "Festival state updated to ANNOUNCED. The festival is now locked and ready for public announcement.",
        festival,
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);
// Get Festival by id
app.get("/festivals/:id", async (req, res) => {
  try {
    console.log("Fetching festival with ID:", req.params.id); // Debug

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).send("Invalid festival ID format.");
    }

    // Fetch festival by ID
    const festival = await Festival.findById(req.params.id).populate(
      "organizers",
      "username"
    );

    if (!festival) {
      return res.status(404).send("Festival not found.");
    }

    // Modify organizers to remove _id
    const modifiedFestival = {
      ...festival.toObject(),
      organizers: festival.organizers.map((organizer) => ({
        username: organizer.username,
      })),
    };

    // Check for Authentication
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      // Return all details except the ID if no authentication token is provided
      const { _id, ...festivalDetails } = modifiedFestival;
      return res.status(200).send(festivalDetails);
    }

    try {
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Find user in the database
      const user = await User.findById(decoded._id);
      if (!user || user.accountStatus === "INACTIVE") {
        return res.status(403).send("Access denied. Invalid token.");
      }

      // Return full festival details
      console.log("Fetched Festival:", modifiedFestival); // Debug
      res.status(200).send(modifiedFestival);
    } catch (error) {
      // Invalid token, return all details except the ID
      const { _id, ...festivalDetails } = modifiedFestival;
      console.log("Invalid token provided, returning limited data.");
      return res.status(200).send(festivalDetails);
    }
  } catch (error) {
    console.error("Error fetching festival:", error); // Debug
    res.status(500).send("An error occurred while fetching the festival.");
  }
});


// Start Assignment Phase
app.post(
  "/festivals/:id/start-assignment",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);
      if (!festival) return res.status(404).send("Festival not found.");
      if (festival.state !== "SUBMISSION") {
        return res
          .status(400)
          .send("Festival must be in SUBMISSION state to start assignment.");
      }
      festival.state = "ASSIGNMENT";
      await festival.save();
      res.status(200).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Start Review Phase
app.post(
  "/festivals/:id/start-review",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);
      if (!festival) return res.status(404).send("Festival not found.");
      if (festival.state !== "ASSIGNMENT") {
        return res
          .status(400)
          .send("Festival must be in ASSIGNMENT state to start review.");
      }
      festival.state = "REVIEW";
      await festival.save();
      res.status(200).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Start Scheduling Phase
app.post(
  "/festivals/:id/start-scheduling",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);

      if (!festival) {
        return res.status(404).send("Festival not found.");
      }

      // Check if the festival is in the REVIEW state
      if (festival.state !== "REVIEW") {
        return res
          .status(400)
          .send(
            "Festival must be in REVIEW state to start the scheduling phase."
          );
      }

      // Update the festival state to SCHEDULING
      festival.state = "SCHEDULING";
      await festival.save();

      res.status(200).send({
        message: "Festival state updated to SCHEDULING.",
        festival,
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  }
);

// Start Submission Phase
app.post(
  "/festivals/:id/start-submission",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const festival = await Festival.findById(req.params.id);

      if (!festival) return res.status(404).send("Festival not found.");
      if (festival.state !== "CREATED") {
        return res
          .status(400)
          .send("Festival must be in CREATED state to start submissions.");
      }

      festival.state = "SUBMISSION";
      await festival.save();
      res.status(200).send(festival);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Create Performance
app.post("/performances", authenticate, async (req, res) => {
  try {
    const { festival, name, description, genre, duration, bandMembers } =
      req.body;

    // Check festival existence and state
    const festivalDoc = await Festival.findById(festival);
    if (!festivalDoc) {
      return res.status(404).send("Festival not found.");
    }

    // Ensure unique performance name within the festival
    const existingPerformance = await Performance.findOne({ festival, name });
    if (existingPerformance) {
      return res
        .status(400)
        .send("Performance name must be unique within the festival.");
    }

    const performance = new Performance({
      festival,
      name,
      description,
      genre,
      duration,
      bandMembers,
      creator: req.user._id,
    });

    await performance.save();
    res.status(201).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Submit Performance
app.post("/performances/:id/submit", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");
    if (performance.creator.toString() !== req.user._id) {
      return res
        .status(403)
        .send("Only the creator can submit this performance.");
    }

    const festival = await Festival.findById(performance.festival);
    if (festival.state !== "SUBMISSION") {
      return res.status(400).send("Festival is not in submission phase.");
    }

    performance.state = "SUBMITTED";
    await performance.save();
    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Review Performance
app.post(
  "/performances/:id/review",
  authenticate,
  authorize(["STAFF", "ORGANIZER"]), // Προστέθηκε και ο ρόλος ORGANIZER
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      // Check if the performance is in the correct state
      if (performance.state !== "SUBMITTED") {
        return res
          .status(400)
          .send("Performance must be in SUBMITTED state to be reviewed.");
      }

      // Check if the logged-in user is the assigned STAFF or ORGANIZER
      if (
        performance.staffAssigned.toString() !== req.user._id &&
        req.user.role !== "ORGANIZER"
      ) {
        return res
          .status(403)
          .send("Only the assigned staff member or an organizer can review this performance.");
      }

      const { score, comments } = req.body;

      if (!score || !comments) {
        return res
          .status(400)
          .send("Score and comments are required for review.");
      }

      performance.review = { score, comments };
      performance.state = "REVIEWED";

      await performance.save();

      res.status(200).send(performance);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);


// Approve Performance
app.post(
  "/performances/:id/approve",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      // Βρες το performance με βάση το ID
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      // Βρες το σχετικό festival
      const festival = await Festival.findById(performance.festival);

      if (!festival) return res.status(404).send("Festival not found.");

      // Έλεγχος αν το festival είναι σε κατάσταση SCHEDULING
      if (festival.state !== "SCHEDULING") {
        return res
          .status(400)
          .send("Festival must be in SCHEDULING state to approve performance.");
      }

      // Ενημέρωση κατάστασης του performance
      performance.state = "APPROVED";
      await performance.save();

      res.status(200).send({
        message: "Performance approved successfully.",
        performance,
      });
    } catch (error) {
      res.status(500).send("An error occurred while approving the performance.");
    }
  }
);


// Final Submission for Performance
app.post("/performances/:id/final-submit", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");

    // Check if the performance is in the right state for final submission
    if (performance.state !== "APPROVED") {
      return res
        .status(400)
        .send("Performance must be in APPROVED state for final submission.");
    }

    // Extract final submission details from the request body
    const { setlist, preferredRehearsalSlots, preferredPerformanceSlots } =
      req.body;

    if (!setlist || !preferredRehearsalSlots || !preferredPerformanceSlots) {
      return res
        .status(400)
        .send("All fields are required for final submission.");
    }

    // Update performance details
    performance.setlist = setlist;
    performance.preferredRehearsalSlots = preferredRehearsalSlots;
    performance.preferredPerformanceSlots = preferredPerformanceSlots;
    performance.state = "FINAL_SUBMITTED";

    await performance.save();

    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Update Performance
app.put("/performances/:id", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");

    // Check if the logged-in user has the role of ARTIST or ORGANIZER
    if (!["ARTIST", "ORGANIZER"].includes(req.user.role)) {
      return res
        .status(403)
        .send("Only users with roles ARTIST or ORGANIZER can update this performance.");
    }

    // Update the performance details
    Object.assign(performance, req.body);
    await performance.save();

    res.status(200).send(performance);
  } catch (error) {
    res.status(400).send(error.message);
  }
});


// Withdraw Performance
app.delete("/performances/:id", authenticate, async (req, res) => {
  try {
    const performance = await Performance.findById(req.params.id);

    if (!performance) return res.status(404).send("Performance not found.");
    
    // Allow withdraw only if the state is CREATED
    if (performance.state !== "CREATED") {
      return res.status(400).send("Only performances in CREATED state can be withdrawn.");
    }

    // Ensure the user has the role of ARTIST
    if (req.user.role !== "ARTIST") {
      return res
        .status(403)
        .send("Only users with the role of ARTIST can withdraw this performance.");
    }

    await performance.deleteOne();
    res.status(200).send("Performance withdrawn successfully.");
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Reject Performance
app.post(
  "/performances/:id/reject",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      // Fetch the associated festival
      const festival = await Festival.findById(performance.festival);
      if (!festival) {
        return res.status(404).send("Festival associated with performance not found.");
      }

      // Check if the festival is in the SCHEDULING state
      if (festival.state !== "SCHEDULING") {
        return res
          .status(400)
          .send("Festival must be in SCHEDULING state to reject a performance.");
      }

      // Check the performance's review score
      if (!performance.review || performance.review.score >= 5) {
        return res
          .status(400)
          .send("Performance cannot be rejected. The review score is acceptable.");
      }

      // Add rejection reason
      const { rejectionReason } = req.body;
      if (!rejectionReason) {
        return res.status(400).send("Rejection reason is required.");
      }

      // Update performance state and rejection reason
      performance.state = "REJECTED";
      performance.rejectionReason = rejectionReason;

      await performance.save();

      res.status(200).send({
        message: "Performance rejected successfully.",
        performance,
      });
    } catch (error) {
      res.status(400).send(error.message);
    }
  }
);



// Assign Staff to Performance
app.post(
  "/performances/:id/assign-staff",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      const { staffId } = req.body;
      const staff = await User.findById(staffId);

      if (!staff || staff.role !== "STAFF") {
        return res.status(400).send("Invalid staff member.");
      }

      performance.staffAssigned = staffId;
      await performance.save();

      res.status(200).send(performance);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Accept Performance During DECISION State
app.post(
  "/performances/:id/accept",
  authenticate,
  authorize(["ORGANIZER"]),
  async (req, res) => {
    try {
      const performance = await Performance.findById(req.params.id);

      if (!performance) return res.status(404).send("Performance not found.");

      // Fetch the associated festival
      const festival = await Festival.findById(performance.festival);
      if (!festival) {
        return res.status(404).send("Festival associated with performance not found.");
      }

      // Check if the festival is in the DECISION state
      if (festival.state !== "DECISION") {
        return res
          .status(400)
          .send("Festival must be in DECISION state to accept a performance.");
      }

      // Check if the performance is in APPROVED state
      if (performance.state !== "APPROVED") {
        return res
          .status(400)
          .send(
            "Performance must be in APPROVED state to be accepted during DECISION."
          );
      }

      // Update performance state to ACCEPTED
      performance.state = "SCHEDULED";

      await performance.save();

      res.status(200).send({
        message: "Performance accepted and scheduled successfully.",
        performance,
      });
    } catch (error) {
      res.status(400).send(error.message);
    }
  }
);


// Add Band Member to Performance
app.post("/performances/:id/add-member", authenticate, authorize(["ARTIST"]), async (req, res) => {
  try {
    const { newMemberUsername } = req.body;

    // Validate the input
    if (!newMemberUsername) {
      return res.status(400).send("Username of the new member is required.");
    }

    // Find the performance by ID
    const performance = await Performance.findById(req.params.id);
    if (!performance) return res.status(404).send("Performance not found.");

    // Ensure the user making the request is the creator of the performance
    if (performance.creator.toString() !== req.user._id) {
      return res.status(403).send("Only the creator of the performance can add band members.");
    }

    // Find the new member in the database
    const newMember = await User.findOne({ username: newMemberUsername });
    if (!newMember) {
      return res.status(404).send("User with the given username not found.");
    }

    // Ensure the user is not already a band member
    if (performance.bandMembers.includes(newMember.username)) {
      return res.status(400).send("User is already a band member.");
    }

    // Add the user to the band members
    performance.bandMembers.push(newMember.username);

    // Optionally, update the user's role to ARTIST for this festival
    newMember.role = "ARTIST";
    await newMember.save();

    // Save the updated performance
    await performance.save();

    res.status(200).send({
      message: "Band member added successfully.",
      performance,
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Search Performances Route
app.get("/performances/search", async (req, res) => {
  try {
    const { name, artist, genre } = req.query;

    const searchCriteria = {};

    if (name) {
      const nameWords = name.split(" ").map((word) => ({
        name: { $regex: word, $options: "i" },
      }));
      searchCriteria.$and = [...(searchCriteria.$and || []), ...nameWords];
    }

    if (artist) {
      const artistWords = artist.split(" ").map((word) => ({
        bandMembers: { $regex: word, $options: "i" },
      }));
      searchCriteria.$and = [...(searchCriteria.$and || []), ...artistWords];
    }

    if (genre) {
      const genreWords = genre.split(" ").map((word) => ({
        genre: { $regex: word, $options: "i" },
      }));
      searchCriteria.$and = [...(searchCriteria.$and || []), ...genreWords];
    }

    let performances = await Performance.find(searchCriteria);

    // Sort performances first by genre, then by name
    performances.sort((a, b) => {
      if (a.genre.toLowerCase() < b.genre.toLowerCase()) return -1;
      if (a.genre.toLowerCase() > b.genre.toLowerCase()) return 1;
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    });

    // Check for Authentication
    const token = req.headers.authorization?.split(" ")[1];
    let userRole = null;

    if (token) {
      try {
        // Decode token to determine role
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded._id);
        if (user && user.accountStatus === "ACTIVE") {
          userRole = user.role;
        }
      } catch (err) {
        console.error("Invalid or expired token provided.");
      }
    }

    // Modify response based on role
    const modifiedPerformances = performances.map((performance) => {
      const performanceObject = performance.toObject();

      if (!userRole || !["ADMIN", "ORGANIZER", "ARTIST"].includes(userRole)) {
        const { _id, ...rest } = performanceObject;
        return rest; // Exclude _id for roles other than ADMIN, ORGANIZER, ARTIST
      }

      return performanceObject; // Include all fields for allowed roles
    });

    res.status(200).send(modifiedPerformances);
  } catch (error) {
    res.status(500).send(error.message);
  }
});




// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


module.exports = app;
