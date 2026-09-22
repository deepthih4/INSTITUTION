const express = require("express");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;

// Serve all files from this folder
app.use(express.static(__dirname));

// Open institution-access.html
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Fallback
app.use((req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Institution Dashboard running on port ${PORT}`);
});
