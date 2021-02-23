// Express is the Node framework that we're using to make our endpoints and middleware
const express = require("express");

//body parser is to transfer the data to your end point
// parses the JSON from incoming post and put request
const bodyParser = require("body-parser");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
// cors is needed to give us the ability to connect
const cors = require("cors");

// // NEW: MySQL database driver
const mysql = require("mysql2/promise");
// creates an instance of express that we use to use our api
const app = express();
// We import and immediately load the `.env` file
require("dotenv").config();

const port = process.env.PORT;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.post("/auth", async function (req, res) {
  try {
    const [[user]] = await req.db.query(
      `
      SELECT * FROM user WHERE email = :email
    `,
      {
        email: req.body.email,
      }
    );

    if (!user) {
      res.json("Email not found");
    }

    console.log("user", user);

    const userPassword = `${user.password}`;

    console.log("userPassword", userPassword);

    const compare = await bcrypt.compare(req.body.password, userPassword);

    console.log("compare", compare);

    if (compare) {
      const payload = {
        userId: user.id,
        email: user.email,
        fname: user.fname,
        lname: user.lname,
        role: 4,
      };

      const encodedUser = jwt.sign(payload, process.env.JWT_KEY);

      res.json(encodedUser);
    } else {
      res.json("Password not found");
    }
  } catch (err) {
    console.log("Error in /auth", err);
  }
});

// // The `use` functions are the middleware - they get called before an endpoint is hit
app.use(async function mysqlConnection(req, res, next) {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (err) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    console.log(err);
    if (req.db) req.db.release();
    throw err;
  }
});

app.use(cors());

app.use(bodyParser.json());

app.post("/register", async function (req, res) {
  try {
    let user;

    // Hashes the password and inserts the info into the `user` table
    await bcrypt.hash(req.body.password, 10).then(async (hash) => {
      try {
        [user] = await req.db.query(
          `
          INSERT INTO user (email, fname, lname, password)
          VALUES (:email, :fname, :lname, :password);
        `,
          {
            email: req.body.email,
            fname: req.body.fname,
            lname: req.body.lname,
            password: hash,
          }
        );

        console.log("user", user);
      } catch (error) {
        res.json("Error creating user");
        console.log("error", error);
      }
    });

    const encodedUser = jwt.sign(
      {
        userId: user.insertId,
        ...req.body,
      },
      process.env.JWT_KEY
    );

    res.json(encodedUser);
  } catch (err) {
    res.json("Error creating authentication user");
    console.log("err", err);
  }
});

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
app.use(async function verifyJwt(req, res, next) {
  try {
    if (!req.headers.authorization) {
      throw (401, "Invalid authorization");
    }

    const [scheme, token] = req.headers.authorization.split(" ");

    if (scheme !== "Bearer") {
      throw (401, "Invalid authorization");
    }

    const payload = jwt.verify(token, process.env.JWT_KEY);

    req.user = payload;
  } catch (err) {
    if (
      err.message &&
      (err.message.toUpperCase() === "INVALID TOKEN" ||
        err.message.toUpperCase() === "JWT EXPIRED")
    ) {
      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit("jwt-error", err, req);
    } else {
      throw (err.status || 500, err.message);
    }
    console.log(err);
  }

  await next();
});

app.get("/emails", async function (req, res) {
  try {
    console.log("/emails success!");

    res.json("/emails success");
  } catch (err) {}
});

app.listen(port, () =>
  console.log(`Demo app listening at http://localhost:${port}`)
);
