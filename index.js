
// // MONGO DB CONECTION STRING: mongodb+srv://hamuan:Alyonka28!@cluster0.jzrp2ae.mongodb.net/
// // Anything with require has to be imported
// const express = require('express');
// const session = require('express-session');
// const MongoStore = require('connect-mongo');
// const bcrypt = require('bcrypt');
// const saltRounds = 12;

// // look for a process.env.PORT valuable exists use that one, otherwise use 3000.
// const port = process.env.PORT || 3000;



require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const fs = require('fs');

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const path = require('path');

const expireTime = 3600000; //expires after 1 hour in ms

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    const html = `
    <h1> Login/Register </h1>
    <button><a href='/login' style='text-decoration:none'>Login</a></button>
    <button><a href='/createUser' style='text-decoration:none'>Register</a></button>
    `;

    res.send(html);
});

// Middleware function to check if the user is authenticated
function requireAuth(req, res, next) {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        next();
    }
}


app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});

app.get('/createUser', (req,res) => {
    var html = `
    Create a user
    <form action='/submitUser' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='username' type='text' placeholder='username'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var email = req.body.email; // Get email from request
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(), // Validate email
        username: Joi.string().alphanum().max(20).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({email, username, password});
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({email: email, username: username, password: hashedPassword}); // Save email to database
    console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
});

app.get('/login', (req,res) => {
    var errorMessage = req.session.errorMessage || '';
    req.session.errorMessage = ''; // Clear the error message after displaying it
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    ${errorMessage}
    `;
    res.send(html);
});


app.post('/loggingin', async (req,res) => {
    var email = req.body.email; 
    var password = req.body.password;

    const schema = Joi.string().email().required(); 
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        req.session.errorMessage = 'Invalid password';
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({email: email}).project({username: 1, password: 1, _id: 1}).toArray(); // Search for user by email

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        req.session.errorMessage = 'Invalid email/password combination';
        res.redirect("/login");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username; // Store username in session
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        console.log("incorrect password");
        req.session.errorMessage = 'Invalid email/password combination';
        res.redirect("/login");
        return;
    }
});


app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    // You are logged in!
    // `;
    // res.send(html);
    res.redirect('/members');
});

// Apply the middleware to all routes
app.use(requireAuth);

// Function to get a random image file from the images folder
function getRandomImage() {
    const imageFolder = './images/random';
    const imageFiles = fs.readdirSync(imageFolder);
    const randomIndex = Math.floor(Math.random() * imageFiles.length);
    return imageFiles[randomIndex];
}

// const fs = require('fs');
// const path = require('path');

// Serve static files from the 'images' folder
app.use('/images', express.static(path.join(__dirname, 'images')));

app.get('/members', (req, res) => {
    // Path to the 'random' subfolder within the 'images' folder
    const imageFolder = './images/random';

    // Read the contents of the 'random' subfolder
    fs.readdir(imageFolder, (err, imageFiles) => {
        if (err) {
            console.error('Error reading random images folder:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Select a random image from the list
        const randomImage = imageFiles[Math.floor(Math.random() * imageFiles.length)];

        // Construct HTML response with the random image
        const html = `
            <h1>Welcome ${req.session.username}!</h1>
            <img src="/images/random/${randomImage}" alt="Random Image" style="max-width: 300px; max-height: 300px;"><br>
            <button><a style='text-decoration:none' href='/logout'>Logout</a></button>`;

        // Send the HTML response
        res.send(html);
    });
});



app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));


app.get('*', (req, res) => {
    // Send the error page with 404 wallpaper
    res.status(404).send(`
        <html>
            <head>
                <style>
                    body {
                        background-image: url('/images/error/spaceman.jpg');
                        background-size: cover;
                        background-repeat: none;
                        height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                    }
                    h1 {
                        color: white;
                        text-align: center;
                    }
                </style>
            </head>
            <body>
                <aside><h1 style="margin-right: 500px;">404 - Page Not Found</h1></aside>
            </body>
        </html>
    `);
});



app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 

