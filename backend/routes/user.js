const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { authenticateToken } = require("./userAuth");

// Sign-up
router.post("/sign-up", async (req, res) => {
  try {
    const { username, email, password, address } = req.body;

    // Validate username length
    if (username.length < 4) {
      return res.status(400).json({
        status: "Error",
        message: "Username must have at least 4 characters.",
      });
    }

    // Validate email format
    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        status: "Error",
        message: "Invalid email format. Please enter a valid email address.",
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({
        status: "Error",
        message: "Password must be at least 6 characters long",
      });
    }

    // Check if username or email already exists
    const usernameExists = await User.findOne({ username });
    const emailExists = await User.findOne({ email });
    if (usernameExists || emailExists) {
      return res.status(400).json({
        status: "Error",
        message: usernameExists
          ? "Username already exists"
          : "Email already exists",
      });
    }

    // Hash the password and save the user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      username,
      password: hashedPassword,
      address,
    });

    await user.save();
    return res.json({
      status: "Success",
      message: "Signup successfully!",
    });
  } catch (error) {
    return res.status(500).json({
      status: "Error",
      message: "Internal server error",
    });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    // Check if the user exists
    if (!user) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    // Compare password
    bcrypt.compare(password, user.password, (err, data) => {
      if (data) {
        // Generate the JWT token
        const token = jwt.sign(
          { username: user.username, role: user.role, id: user._id }, 
          "bookStore123", 
          { expiresIn: "30d" }
        );

        return res.json({
          _id: user._id,
          role: user.role,
          token,
        });
      } else {
        return res.status(400).json({ message: "Invalid credentials" });
      }
    });
  } catch (error) {
    return res.status(500).json({ message: "Internal Error" });
  }
});

// Get User Profile Data
router.get("/getUserData", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id); // Use id from token
    return res.status(200).json(user);
  } catch (error) {
    return res.status(500).json({ message: "An error occurred" });
  }
});

// Update User Address
router.put("/update-user-address", authenticateToken, async (req, res) => {
  try {
    const { address } = req.body;
    await User.findByIdAndUpdate(req.user.id, { address }); // Use id from token
    return res.status(200).json({
      status: "Success",
      message: "Address updated successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "An error occurred" });
  }
});

module.exports = router;
