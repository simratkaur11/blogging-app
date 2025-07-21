import express from 'express';
import mongoose from 'mongoose';
import User from './User.js'; 
import cors from 'cors';
import PostModel from './models/post.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import fs from 'fs'; 
dotenv.config();
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import Comment from './models/comment.js';

const allowedOrigins = [
  'http://localhost:3000',
  'https://frontend-kappa-eight-42.vercel.app'
];

const app=express();
app.use(express.json())

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin like mobile apps or curl
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads'));  // folder must exist or create it
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `${name}-${Date.now()}${ext}`);
  }
});

const uploadmiddleware = multer({ storage });


const upload = multer({ dest: "uploads/" }); // Temporary file store



app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// mongoose.connect("mongodb+srv://simratkaur2244:simrat@cluster0.0ltm5y1.mongodb.net/blogapp?retryWrites=true&w=majority&appName=Cluster0")
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected!'))
.catch(err => console.error('MongoDB connection error:', err));

app.post('/register', async (req, res) => {
  const { username,email, password } = req.body;
  try {
    // Hash the password before saving
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    // Create user with hashed password
    const userDoc = await User.create({
      username,
      email,
      password: hashedPassword,
    });

    res.json(userDoc);
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(400).json(err);
  }
});


function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const secret = process.env.JWT_SECRET;
    const decoded = jwt.verify(token, secret);
    req.user = decoded; // Attach user info to request
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    return res.status(401).json({ message: 'Invalid token' });
  }
}



app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // 1. Check if user exists
    const userDoc = await User.findOne({  username  });
    if (!userDoc) {
      return res.status(400).json({ message: 'User not found' });
    }

    // 2. Check if password is correct
    const isPasswordCorrect = bcrypt.compareSync(password, userDoc.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: 'Incorrect password' });
    }
    const secret=process.env.JWT_SECRET;
    // 3. Login successful
    const token = jwt.sign({ id: userDoc._id, username }, secret, { expiresIn: '1h' });

    res.cookie('token', token, {
        httpOnly: true,
        secure: true,         // true in production with HTTPS
        sameSite: 'none',       // or 'strict' if needed
    }).json({  id: userDoc._id,username: userDoc.username });

    } catch (err) { 
         console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.get('/profile', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    
    try {
        const secret = process.env.JWT_SECRET;
        const decoded = jwt.verify(token, secret);
        res.json({ username: decoded.username, userId: decoded.id });
    } catch (err) {
        console.error('Token verification error:', err);
        res.status(401).json({ message: 'Invalid token' });
    }
    }
);

app.post('/logout',(req,res)=>{
  res.cookie('token','').json('ok')
})

app.post('/post',authMiddleware, uploadmiddleware.single('file'), async (req, res) => {
  const { title, summary, content } = req.body;
  const { file } = req;

  // do something with req.body and req.file
   if (!file) return res.status(400).json({ error: "No file uploaded" });

  const filePath = `/uploads/${file.filename}`; // accessible via frontend
   const postdoc=await PostModel.create({
    title,
    summary,
    content,
    cover: filePath,
    author:req.user.id // save the file path in the database
  })
  res.json(
    postdoc
  );
});

app.get('/post', async (_req, res) => {
  const posts=await PostModel.find()
  .populate('author', ['username'])
  .sort({ createdAt: -1 })
  .limit(4);
  res.json(posts);
})

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const post = await PostModel.findById(id).populate('author', ['username']);
 
  res.json(post);
});

app.delete('/post/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const post = await PostModel.findById(id);

    if (!post) return res.status(404).json({ message: "Post not found" });

    // Only the author can delete
    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({ message: "You are not authorized to delete this post" });
    }

    await PostModel.findByIdAndDelete(id);
    res.status(200).json({ message: "Post deleted successfully" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ message: "Error deleting post" });
  }
});

app.put('/post/:id', authMiddleware, uploadmiddleware.single("cover"), async (req, res) => {
  const { title, summary, content } = req.body;

  try {
    const post = await PostModel.findById(req.params.id);
    if (!post) return res.status(404).json("Post not found");

    if (post.author.toString() !== req.user.id)
      return res.status(403).json("Unauthorized");

    post.title = title;
    post.summary = summary;
    post.content = content;

    if (req.file) {
      const { path: filePath, originalname } = req.file;
      const ext = path.extname(originalname);
      const newPath = `${filePath}${ext}`;

      fs.renameSync(filePath, newPath);
      post.cover = `/uploads/${path.basename(newPath)}`; // this is accessible via frontend
    }

    const updatedPost = await post.save();
    res.json(updatedPost);
  } catch (err) {
    console.error(err);
    res.status(500).json("Error updating post");
  }
});

app.post('/post/:id/comment', authMiddleware, async (req, res) => {
  const { content } = req.body;
  const { id } = req.params;

  try {
    const newComment = await Comment.create({
      content,
      author: req.user.id,
      post: id
    });

    res.status(201).json(newComment);
  } catch (err) {
    res.status(500).json({ message: 'Failed to post comment' });
  }
});

app.get('/post/:id/comments', async (req, res) => {
  const { id } = req.params;

  try {
    const comments = await Comment.find({ post: id })
      .populate('author', 'username')
      .sort({ createdAt: -1 });

    res.json(comments);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch comments' });
  }
});



app.listen(4000);