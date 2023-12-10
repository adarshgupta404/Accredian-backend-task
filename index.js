import express, { response } from "express";
import mysql from 'mysql';
import cors from "cors";
import jwt from "jsonwebtoken";
import bycrpt from "bcrypt";
import dotenv from "dotenv"
import cookieParser from "cookie-parser";
const salt = 16;
dotenv.config();
 
const app = express();
app.use(express.json());
app.use(
    cors({
      origin: ["https://accredian-frontend-task-one-kappa.vercel.app"],
      methods: ["POST", "GET"],
      credentials: true,
    })
  );
app.options("*", cors());
app.use(cookieParser());
const PORT = process.env.PORT || 8000;
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to database');
});

app.post('/register', (req, res) => {
    const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
    const insertUserQuery = "INSERT INTO users (username, email, password) VALUES (?)";
    db.query(checkEmailQuery, [req.body.email], (err, results) => {
        if (err) {
            return res.json({ Error: "Error in checking email existence!" });
        }
        if (results.length > 0) {
            return res.json({ Error: "Email already registered!" });
        } else {
            bycrpt.hash(req.body.password.toString(), salt, (err, hash) => {
                if (err) {
                    return res.json({ Error: "Error in hashing!" });
                }

                const values = [
                    req.body.username,
                    req.body.email,
                    hash
                ];
                db.query(insertUserQuery, [values], (err, result) => {
                    if (err) {
                        return res.json({ Error: "Error in inserting the values!" });
                    }

                    return res.json({ Status: "Success" });
                });
            });
        }
    });
});

app.post('/login', (req, res) => {
    const sqlq = "SELECT * FROM users WHERE email = ? OR username = ?";
    db.query(sqlq, [req.body.email, req.body.username], (err, data) => {
        if (err) return res.json({ Error: "Login Error in server" });
        if (data.length == 0) return res.json({ Error: "No email found register please" })
        if (data.length > 0) {
            bycrpt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) {
                    return res.json({ Error: "Login Error in server" });
                }
                if (response) {
                    const name = data[0].username;
                    const token = jwt.sign({name}, "jwt-secret-key", {expiresIn:'1d'});
                    res.cookie('token', token);
                    return res.json({ Status: "Success" });
                } else {
                    return res.json({ Error: "Password not matched" });
                }
            });
        } else {
            return res.json({ Error: "No matching email or username found" });
        }
    });
});

const verifyUser = (req, res, next)=>{
    const token = req.cookies.token;
    if(!token){
        return res.json({ Error: "You are not authenticated!" });
    }
    else{
        jwt.verify(token, "jwt-secret-key", (err, decoded)=>{
            if(err){
                return res.json({ Error: "Token incorrect!" });
            }
            else{
                req.name = decoded.name;
                next();
            }
        })
    }
}

app.get("/logout", (re, res)=>{
    res.clearCookie('token')
    return res.json({Status:"Success"})
})

app.get('/',verifyUser, (req, res)=>{
    return res.json({Status:"Success", name:req.name})
})

app.listen(PORT, ()=>{
    console.log("Listening to port "+PORT)
})







