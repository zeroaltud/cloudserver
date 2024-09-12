const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const mongoose = require('mongoose');
const { Schema } = mongoose;

// SSL certificates
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

const app = express();
const PORT = 3000;

// Connect to MongoDB
mongoose.connect('mongodb+srv://ronivrolijks:oparoniv@cluster0.4pcpt9x.mongodb.net/webserver', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// Define a schema to store file metadata
const fileSchema = new Schema({
  filename: String,
  folder: String,
  createdAt: { type: Date, default: Date.now }
});
const File = mongoose.model('File', fileSchema);

// Define a schema to store folder metadata
const folderSchema = new Schema({
  name: String,
  parent: String,
  createdAt: { type: Date, default: Date.now }
});
const Folder = mongoose.model('Folder', folderSchema);

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads'); // Save files directly to the `uploads` directory
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage: storage });

// Middleware for parsing form data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // To handle JSON requests

// Simple password authentication
const PASSWORD = 'your_secure_password'; // Set a strong password here

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) {
    res.setHeader('WWW-Authenticate', 'Basic');
    return res.status(401).send('Authentication required.');
  }

  const credentials = Buffer.from(auth.split(' ')[1], 'base64').toString('ascii');
  const [username, password] = credentials.split(':');

  if (password === PASSWORD) {
    return next();
  } else {
    return res.status(403).send('Access Denied: Incorrect Password.');
  }
}

// Serve the dashboard (Password-protected route)
app.get('/dashboard', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// File upload route
app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  const { folder } = req.body;
  const uploadedFile = new File({
    filename: req.file.filename,
    folder: folder || 'root'
  });
  
  await uploadedFile.save();
  res.redirect('/dashboard');
});

// Download file route
app.get('/download/:filename', authMiddleware, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).send('File not found');
  }
});

// Delete file route
app.post('/delete', authMiddleware, async (req, res) => {
  const { filename } = req.body;
  const filePath = path.join(__dirname, 'uploads', filename);
  
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    await File.deleteOne({ filename });
    res.redirect('/dashboard');
  } else {
    res.status(404).send('File not found');
  }
});

// Create a folder
app.post('/create-folder', authMiddleware, async (req, res) => {
  const { folderName, parentFolder } = req.body;
  const folder = new Folder({
    name: folderName,
    parent: parentFolder || 'root'
  });
  
  await folder.save();
  res.redirect('/dashboard');
});

// Delete a folder
app.post('/delete-folder', authMiddleware, async (req, res) => {
  const { folderName } = req.body;
  
  const folderToDelete = await Folder.findOne({ name: folderName }).exec();
  if (folderToDelete) {
    await Folder.deleteOne({ name: folderName });
    await File.deleteMany({ folder: folderName });
    res.redirect('/dashboard');
  } else {
    res.status(404).send('Folder not found');
  }
});

// Get files and folders in a directory
app.get('/files-and-folders', authMiddleware, async (req, res) => {
  const folder = req.query.folder || 'root';

  const files = await File.find({ folder }).exec();
  const folders = await Folder.find({ parent: folder }).exec();

  res.json({
    files: files.map(file => ({ filename: file.filename })),
    folders: folders.map(folder => ({ name: folder.name }))
  });
});

// HTTPS server with SSL encryption
https.createServer(options, app).listen(PORT, () => {
  console.log(`HTTPS Server running on port ${PORT}`);
});
