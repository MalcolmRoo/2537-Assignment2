require('node:dns/promises').setServers(['1.1.1.1', '8.8.8.8']);
require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default; 
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const Joi = require('joi');
const mongoSanitizer = require('mongo-sanitizer').default;

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.HOST;
const mongodb_user = process.env.USER;
const mongodb_password = process.env.DATABASE_PASS;
const mongodb_session_database = process.env.SESSION_DB;
const mongodb_user_database = process.env.USER_DB;

const node_session_secret = process.env.NODE_SECRET;

app.set('view engine', 'ejs');

const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.json());

app.use(mongoSanitizer({
    replaceWith: '_'
}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: {
        secret: process.env.MONGO_SESSION_SECRET
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

//Routes
app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated,
        username: req.session.username
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    var username = req.body.username;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);

    if(validationResult.error != null){
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();

    if(result.length != 1){
        res.send(`
        <p>Invalid email/password combintation.</p>
        <a href="/login"><button>Try Again</button></a>
        `);
        return;
    }

    if(await bcrypt.compare(password, result[0].password)){
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/");
        return;
    } else {
        res.send(`
        <p>Invalid email/password combintation.</p>
        <a href="/login"><button>Try Again</button></a>
        `);
        
        return;
    }
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().max(45).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({username, email, password});

    var html = "";
    if(!username){
        html += `<p>Name is required</p>
        <a href="/signup"><button>Try Again</button></a>`;   
    } else if (!email) {
         html += `<p>Email is required</p>
        <a href="/signup"><button>Try Again</button></a>`;
    } else if (!password){
         html += `<p>Password is required</p>
        <a href="/signup"><button>Try Again</button></a>`;
    } else {

        if(validationResult.error != null){
            console.log(validationResult.error);
            res.redirect("/signup");
            return;
        }

        var hashedPassword = bcrypt.hashSync(password, saltRounds);
        await userCollection.insertOne({username: username, email: email, password: hashedPassword});

        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/members");
        return;
    }

    res.send(html);
});

app.get('/members', (req,res) => {
    res.render('members', {
        authenticated: req.session.authenticated,
        username: req.session.username
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.render('logout');
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
    res.status(404);
    res.render('404');
})

//Start Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});