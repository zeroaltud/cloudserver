const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { Schema } = mongoose;

const app = express();
const PORT = 80;
const SECRET_KEY = crypto.createHash('sha256').update('decrypt1234').digest('base64').substring(0, 32);
const IV_LENGTH = 16;
const ENCRYPTION_ALGORITHM = 'aes-256-ctr';

mongoose.connect('mongodb+srv://ronivrolijks:oparoniv@cluster0.4pcpt9x.mongodb.net/webserver', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

const fileSchema = new Schema({
  filename: String,
  folder: String,
  createdAt: { type: Date, default: Date.now }
});
const File = mongoose.model('File', fileSchema);



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

Password.findOne().then(doc => {
  if (!doc) {
    const newPassword = new Password({ password: 'ilikedecrypt' });
    newPassword.save();
  }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads'); 
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage: storage });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const PASSWORD = 'your_secure_password'; // need to change

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
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, Buffer.from(SECRET_KEY, 'utf8'), iv);
  
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return { iv, encrypted };
}

function decryptFile(iv, data) {
  if (iv.length !== IV_LENGTH) {
    throw new Error('Invalid IV length');
  }

  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, Buffer.from(SECRET_KEY, 'utf8'), iv);
  
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted;
}
app.get('/dashboard', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'front/dashboard.html'));
});

app.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  const { folder } = req.body;
  const filePath = path.join('uploads', req.file.filename);

  fs.readFile(req.file.path, (err, data) => {
    if (err) throw err;
    const { iv, encrypted } = encryptFile(data);

    const finalBuffer = Buffer.concat([iv, encrypted]);
    fs.writeFile(filePath, finalBuffer, (err) => {
      if (err) throw err;
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
app.get('/download/:filename', async (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }
  const passwordDoc = await Password.findOne();
  if (!passwordDoc) {
    return res.status(500).send('Decryption password not set in database.');
  }

  const storedPassword = passwordDoc.password;
  const userPassword = req.query.password;

  if (userPassword !== storedPassword) {
    return res.status(403).send('Incorrect password for decryption.');
  }
  fs.readFile(filePath, (err, fileData) => {
    if (err) return res.status(500).send('Error reading file');
    const iv = fileData.slice(0, IV_LENGTH);
    const encryptedData = fileData.slice(IV_LENGTH);

    try {
      const decryptedData = decryptFile(iv, encryptedData);
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
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    await File.deleteOne({ filename });
    
    res.send('File deleted successfully.');
  } else {
    res.status(404).send('File not found.');
  }
});
app.post('/create-folder', authMiddleware, async (req, res) => {
  const { folderName, parentFolder } = req.body;
  const folder = new Folder({
    name: folderName,
    parent: parentFolder || 'root'
  });

  await folder.save();
  res.redirect('/dashboard');
});

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
