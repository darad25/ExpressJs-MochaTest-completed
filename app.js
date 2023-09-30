require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const { AuthMiddleware } = require("./auth_middleware.js"); // Update the path accordingly

const app = express();
const PORT = process.env.PORT;

// Middleware setup
app.use(bodyParser.json());
app.use(cookieParser());
app.use(AuthMiddleware.sessionManager);

// Mock database (for demonstration purposes)
const users = [];

// Register a new user
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({
    uid: users.length + 1,
    email,
    password: hashedPassword,
    first_name: "John",
    last_name: "Doe",
  });
  res.send("User registered successfully!");
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(400).send("User not found");
  }
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(400).send("Invalid password");
  }
  var response = AuthMiddleware.newSession(user, req, res, false);
  res.send(response);
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy();
  res.clearCookie("refreshToken");
  res.clearCookie("accessToken");
  res.send("Logged out successfully.");
});

// Protected route using the authenticateHybrid middleware
app.get("/protected", AuthMiddleware.authenticateHybrid, (req, res) => {
  res.send(
    `Hello, ${req.locals.user.first_name}! You have accessed a protected route.`,
  );
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;