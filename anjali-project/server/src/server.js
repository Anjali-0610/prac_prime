import express from "express";
import sanitiseData from "./helper/verification.js";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const port = 3000;

app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.get("/submit", async (req, res) => {
    const reqData = req.query;
    console.log("reqData : ", reqData);
    // if (!reqData.email || !reqData.password) {
    //     res.status(400).send("Bad Request!!");
    //     return;
    // }
    const isSanitised = sanitiseData({
        email: reqData.email,
        password: reqData.password,
    });
    console.log("isSanitised : ", isSanitised);
    if (!isSanitised) {
        console.log("Forbidden!!");
        res.status(403).send("Forbidden!!");
    }
    console.log("Data received successfully!!");
    res.json({ message: "Data received successfully!!" });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
