const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto'); // Encryption library
const { Schema } = mongoose;

const app = express();
const PORT = 80;
const SECRET_KEY = crypto.createHash('sha256').update('decrypt1234').digest('base64').substring(0, 32);
const IV_LENGTH = 16; // For AES, IV length is always 16 bytes
const ENCRYPTION_ALGORITHM = 'aes-256-ctr';

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

const passwordSchema = new Schema({
  password: String
});
const Password = mongoose.model('Password', passwordSchema);

// Save the password to the database (Run this once when the server starts, or in a seeder)
Password.findOne().then(doc => {
  if (!doc) {
    const newPassword = new Password({ password: 'ilikedecrypt' });
    newPassword.save();
  }
});

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

function encryptFile(data) {
  const iv = crypto.randomBytes(IV_LENGTH); // Generate a random 16-byte IV
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, Buffer.from(SECRET_KEY, 'utf8'), iv);
  
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  
  // Return both the IV and the encrypted data
  return { iv, encrypted };
}

function decryptFile(iv, data) {
  // Ensure the IV is 16 bytes
  if (iv.length !== IV_LENGTH) {
    throw new Error('Invalid IV length');
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, Buffer.from(SECRET_KEY, 'utf8'), iv);
  
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted;
}

// Serve the dashboard (Password-protected route)
app.get('/dashboard', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'front/dashboard.html'));
});

app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  const { folder } = req.body;
  const filePath = path.join('uploads', req.file.filename);

  fs.readFile(req.file.path, (err, data) => {
    if (err) throw err;

    // Encrypt the file
    const { iv, encrypted } = encryptFile(data);

    // Combine IV and encrypted data into one buffer and save
    const finalBuffer = Buffer.concat([iv, encrypted]);
    fs.writeFile(filePath, finalBuffer, (err) => {
      if (err) throw err;

      // Save metadata
      const uploadedFile = new File({
        filename: req.file.filename,
        folder: folder || 'root'
      });

      uploadedFile.save()
        .then(() => res.redirect('/dashboard'))
        .catch(err => res.status(500).send('Error saving file metadata'));
    });
  });
});

// Middleware to check decryption password
app.get('/download/:filename', async (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);
  
  // Ensure file exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }
  
  // Get the decryption password from the database
  const passwordDoc = await Password.findOne();
  if (!passwordDoc) {
    return res.status(500).send('Decryption password not set in database.');
  }

  const storedPassword = passwordDoc.password;
  const userPassword = req.query.password; // Password from query parameter

  // Check if the provided password matches
  if (userPassword !== storedPassword) {
    return res.status(403).send('Incorrect password for decryption.');
  }

  // Read file data
  fs.readFile(filePath, (err, fileData) => {
    if (err) return res.status(500).send('Error reading file');

    // Extract IV and encrypted data
    const iv = fileData.slice(0, IV_LENGTH);
    const encryptedData = fileData.slice(IV_LENGTH);

    try {
      // Decrypt the data
      const decryptedData = decryptFile(iv, encryptedData);

      // Send the decrypted file to the client
      res.setHeader('Content-Disposition', `attachment; filename=${req.params.filename}`);
      res.send(decryptedData);
    } catch (error) {
      res.status(500).send('Error decrypting file');
    }
  });
});

app.post('/delete-file', authMiddleware, async (req, res) => {
  const { filename } = req.body;
  const filePath = path.join(__dirname, 'uploads', filename);

  // Check if file exists
  if (fs.existsSync(filePath)) {
    // Delete the file from the filesystem
    fs.unlinkSync(filePath);
    
    // Remove file metadata from MongoDB
    await File.deleteOne({ filename });
    
    res.send('File deleted successfully.');
  } else {
    res.status(404).send('File not found.');
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

http.createServer(app).listen(PORT, () => {
  console.log(`HTTP Server running on port ${PORT}`);
});
