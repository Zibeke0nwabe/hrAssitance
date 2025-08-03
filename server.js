require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { GoogleGenAI } = require('@google/genai');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// ENV
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// MongoDB Connect
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error(err));

// ==== Models ====
const adminSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const Admin = mongoose.model('Admin', adminSchema);

const managerSchema = new mongoose.Schema({
  username: String,
  password: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
});
const Manager = mongoose.model('Manager', managerSchema);

const warningSchema = new mongoose.Schema({
  manager: { type: mongoose.Schema.Types.ObjectId, ref: 'Manager' },
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  employeeName: String,
  warningText: String,
  aiVerdict: String,
  aiExplanation: String,
  suggestedAction: String,
  adminFeedback: String,
  createdAt: { type: Date, default: Date.now },
});
const Warning = mongoose.model('Warning', warningSchema);

// ==== Middleware ====
const authMiddleware = (roles = []) => (req, res, next) => {
  const token = req.query.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.redirect('/');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (roles.length && !roles.includes(decoded.role)) {
      return res.status(403).send('Access Denied');
    }
    req.user = decoded;
    next();
  } catch {
    res.status(401).send('Invalid Token');
  }
};

// ==== Gemini AI Config ====
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });

const systemPrompt = `
You are an AI-powered HR assistant. Your job is to evaluate employee warnings submitted by managers and determine if they are valid according to general HR practices.
Consider the following:
- Is there clear evidence?
- Is it specific and professional?
- Does it align with typical HR policy violations?
- Is the tone appropriate?

Respond with:
1. Verdict: [Valid Warning | Needs More Information | Unjustified Warning]
2. Explanation: [Why the verdict was reached]
3. Suggested HR action (if applicable)
`;

async function evaluateWarning(manager, employee, warningText) {
  const config = { systemInstruction: [{ text: systemPrompt }] };
  const contents = [{
    role: 'user',
    parts: [{ text: JSON.stringify({ manager, employee, warning: warningText }) }],
  }];
  const model = 'gemini-2.5-pro';

  const result = await ai.models.generateContent({ model, config, contents });
  const responseText = result.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
  console.log('AI response content:\n', responseText);

  return responseText;
}

function parseAIResponse(text) {
  
  const verdict = text.match(/Verdict:\s*(.*)/i)?.[1] ?? '';
  const explanation = text.match(/Explanation:\s*((.|\n)*?)Suggested/i)?.[1]?.trim() ?? '';
  const suggestedAction = text.match(/Suggested HR action:\s*((.|\n)*)$/i)?.[1]?.trim() ?? '';
  return [verdict, explanation, suggestedAction];
}

// ========== Routes ==========

// Landing page
app.get('/', (req, res) => {
  res.redirect('/login/manager');
});

// ===== Auth Routes =====
app.get('/register-admin', (req, res) => {
  res.render('registerAdmin');
});

app.post('/register-admin', async (req, res) => {
  const { username, password } = req.body;
  const existing = await Admin.findOne({ username });
  if (existing) return res.send('Admin already exists');

  const hash = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hash });
  res.redirect('/login/admin');
});

app.get('/login/admin', (req, res) => {
  res.render('loginAdmin');
});

app.post('/login/admin', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.send('Invalid admin credentials');
  }

  const token = jwt.sign({ id: admin._id, role: 'admin', username }, JWT_SECRET);
  res.redirect(`/admin/home?token=${token}`);
});

// ===== Admin Routes =====
app.get('/login/manager', (req, res) => {
  res.render('loginManager');
});

app.post('/login/manager', async (req, res) => {
  const { username, password } = req.body;
  const manager = await Manager.findOne({ username });
  if (!manager || !(await bcrypt.compare(password, manager.password))) {
    return res.send('Invalid manager credentials');
  }

  const token = jwt.sign({ id: manager._id, role: 'manager', username }, JWT_SECRET);
  res.redirect(`/manager/home?token=${token}`);
});

app.get('/admin/home', authMiddleware(['admin']), async (req, res) => {
  const decoded = req.user;
  const warnings = await Warning.find({ admin: decoded.id })
    .populate('manager', 'username')
    .sort({ createdAt: -1 });
  res.render('adminHome', { username: decoded.username, warnings, token: req.query.token });
});

app.get('/admin/managers', authMiddleware(['admin']), async (req, res) => {
  const decoded = req.user;
  const managers = await Manager.find({ createdBy: decoded.id });
  res.render('adminManagers', { username: decoded.username, managers, token: req.query.token });
});

app.get('/admin/register-manager', (req, res) => {
  const token = req.query.token;
  res.render('registerManager', { token });
});

app.post('/admin/create-manager', authMiddleware(['admin']), async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await Manager.create({
    username,
    password: hash,
    createdBy: req.user.id,
  });
  res.redirect(`/admin/managers?token=${req.query.token}`);
});

app.get('/admin/warning/:id', authMiddleware(['admin']), async (req, res) => {
  try {
    const warning = await Warning.findById(req.params.id).populate('manager', 'username');
    if (!warning) return res.status(404).send('Warning not found');
    res.render('adminWarningDetails', {
      warning,
      token: req.query.token,
      username: req.user.username,
      userRole: 'admin'
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.post('/admin/warning/:id/feedback', authMiddleware(['admin']), async (req, res) => {
  const { feedback } = req.body;
  const token = req.query.token;

  try {
    await Warning.findByIdAndUpdate(req.params.id, { adminFeedback: feedback });
    res.redirect(`/admin/warning/${req.params.id}?token=${token}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to submit feedback');
  }
});

// ===== Manager Routes =====
app.get('/manager/home', authMiddleware(['manager']), async (req, res) => {
  const decoded = req.user;
  const warnings = await Warning.find({ manager: decoded.id })
    .populate('admin', 'username')
    .sort({ createdAt: -1 });
  res.render('managerHome', { username: decoded.username, warnings, token: req.query.token });
});
app.get('/manager/warnings', authMiddleware(['manager']), async (req, res) => {
  const decoded = req.user;
  const { search = '', page = 1 } = req.query;
  const limit = 8;
  const skip = (page - 1) * limit;

  const query = {
    manager: decoded.id,
    employeeName: { $regex: search, $options: 'i' },
  };

  const [warnings, count] = await Promise.all([
    Warning.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit),
    Warning.countDocuments(query),
  ]);

  const totalPages = Math.ceil(count / limit);

  res.render('managerWarnings', {
    username: decoded.username,
    warnings,
    token: req.query.token,
    search,
    currentPage: parseInt(page),
    totalPages,
  });
});
app.get('/manager/warning/:id', authMiddleware(['manager']), async (req, res) => {
  try {
    const warning = await Warning.findById(req.params.id).populate('manager', 'username');
    if (!warning) return res.status(404).send('Warning not found');
    
    res.render('adminWarningDetails', {
      warning,
      token: req.query.token,
      username: req.user.username,
      userRole: 'manager'
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/manager/submit-warning', authMiddleware(['manager']), (req, res) => {
  const token = req.query.token;
  res.render('submitWarning', { token, username: req.user.username });
});
app.post('/manager/submit-warning', async (req, res) => {
  const { employeeName, warningText, token } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const manager = await Manager.findById(decoded.id);

    const aiResult = await evaluateWarning(decoded.username, employeeName, warningText);
    const [aiVerdict, aiExplanation, suggestedAction] = parseAIResponse(aiResult);

    const newWarning = await Warning.create({
      manager: manager._id,
      admin: manager.createdBy,
      employeeName,
      warningText,
      aiVerdict,
      aiExplanation,
      suggestedAction,
    });

    res.redirect(`/manager/warning/${newWarning._id}?token=${token}`);
  } catch (err) {
    console.error(err);
    res.send('Failed to evaluate warning');
  }
});

// ===== Start Server =====
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
