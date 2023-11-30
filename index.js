require('dotenv').config()

const express = require('express')
const path = require('path')
const mysql2 = require('mysql2')
const jwt = require('jsonwebtoken')
const session = require('express-session');
const { access } = require('fs');
const app = express()

const patientRoute = require('./routes/patients')
const doctorRoute = require('./routes/doctors')
const pharmacyRoute = require('./routes/pharmacy')
const companyRoute = require('./routes/company')
const drugRoute = require('./routes/drugs')
app.use('/patients', patientRoute)
app.use('/doctors', doctorRoute)
app.use('/pharmacy', pharmacyRoute)
app.use('/company', companyRoute)
app.use('/drugs', drugRoute)

const users = []
let refreshTokens = []

app.use(express.static(path.join(__dirname, 'public'))) // Acess the right folder

app.use(express.json()) // Allow express to send json

// Use express-session middleware
app.use(session({
    secret: 'c75ue5wsh8syozant1to5', // Change this to a strong, secure secret key
    resave: false,
    saveUninitialized: true,
}));

const connection = mysql2.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'ddapp',
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to the database: ' + err.stack);
        return;
    }
    console.log('Connected to the database');
});

app.listen(3000 , ()=>{
    console.log("API up and running")
})

app.post('/register', (req,res)=>{
    //Retrieve the data from the body req
    const userType = req.body.userType
    const SSN = req.body.SSN
    const password = req.body.password
    
    //Test recieval
    console.log(req.body)

    if (req.body == null || req.body.SSN ==null || req.body.userType == null || req.body.password ==null ) {
        return res.status(500).json({ message: 'Please fill in all the fields' });
    }

    const sql = 'SELECT ID_SSN, User_Type, Password FROM api_access WHERE ID_SSN = ? AND User_Type = ?'
    connection.query(sql, [SSN, userType], (err,results)=>{
        if (err) return res.status(500).json( {error : "Internal Server Error" + err.stack})
        if (results.length > 0) {console.log("User already exists");return res.status(401).json({ message: 'User already exists' })}

        //Insert user 
        const insertSql = 'INSERT INTO api_access(ID_SSN, User_Type, Password) VALUES (?, ?, ?)'
        connection.query(insertSql, [SSN, userType, password], (err,complete)=>{
            //Results
            if (err) return res.status(500).json( {message : "Internal Server Error. Not Registered"})
            console.log(results);

            // window.alert("Registration successful. Proceed to login")
            // console.log({ message: 'Registration successful' });
            return res.status(200).json({ message: 'Registration successful. Proceed to login page.' });
        })  
    })
})

app.post('/login', (req, res) => {
    const userType = req.body.userType;
    const SSN = req.body.SSN;
    const password = req.body.password;
  
    console.log(req.body);

    if (req.body == null || req.body.SSN ==null || req.body.userType == null || req.body.password ==null ) {
        return res.status(500).json({ message: 'Please fill in all the fields' });
    }
  
    const sql = 'SELECT ID_SSN, User_type, Password, Login_Time FROM api_access  WHERE ID_SSN = ? AND User_Type = ?';
    connection.query(sql, [SSN, userType], (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Internal Server Error' + err.stack });
      }

      
  
      if (results.length === 0) {
        return res.status(401).json({ message: 'No such user exists' });
      }

      //console.log(results);
  
      if (password === results[0].Password) {
        const user = {
          SSN: results[0]['ID_SSN'],
          userType: results[0].User_type
        };
  
        // Store user information in the session
        req.session.user = user;
        console.log(user);

  
        const updateQuery = 'UPDATE api_access SET Login_Time = CURRENT_TIMESTAMP WHERE ID_SSN = ? AND User_Type = ?';
        connection.query(updateQuery, [SSN, userType], (updateError) => {
          if (updateError) {
            console.error('Error updating last login timestamp: ' + updateError.stack);
            return res.status(500).json({ message: 'Internal Server Error' });
          }

          const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign({ SSN: user.SSN }, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken);
          
          console.log('Login Successful');
          return res.status(200).json({ message: 'Login successful. Welcome to the API',
          accessToken: accessToken,
          refreshToken: refreshToken
         });
          
        });
      } else {
        console.log('Password Mismatch');
        return res.status(401).json({ message: 'Invalid credentials' });
      }
    });
})

app.get('/tokens', (req, res) => {
    //To get the access token
      const user = req.session.user;
  
      if (!user) {
          return res.status(401).json({ message: 'Unauthorized' });
      }
      console.log(user);
  
      const accessToken = generateAccessToken(user.SSN)
      const refreshToken = jwt.sign(user.SSN, process.env.REFRESH_TOKEN_SECRET)
      refreshTokens.push(refreshToken)
      
      res.status(200).json({ accessToken: accessToken , refreshToken : refreshToken});
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authorization Failed' });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, userData) => {
        if (err) return res.status(403).json({ message: 'Token verification failed' });
        req.session.user = userData; // Store user data in session for later use
        next();
    });
}

function generateAccessToken(user) {
    const payload = { SSN: user.SSN }; // Extract the SSN from the user object
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '1h'});
}
  
app.post('/refresh', (req,res)=>{
  //Generate a new access token
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err,user)=>{
      if(err) return res.sendStatus(403)
      const accessToken = generateAccessToken({SSN : user.SSN})
      res.json({accessToken : accessToken})
  })

})

// Get all api users using token authentication

// List of all users (secure endpoint)
app.get('/users', authenticateToken, (req, res) => {
    // Retrieve user from session
    const user = req.session.user;

    if (!user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    connection.query(
        'SELECT * FROM doctors, patients, admins, apiusers, pharmacies, pharmaceutical_companies',
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Internal Server Error' });
            res.status(200).json(results);
        }
    );
});

// One user’s details by email/ id (secure endpoint)
app.get('/users/:id', authenticateToken, (req, res) => {
    const user = req.session.user;

    if (!user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const userId = req.params.id;

    connection.query(
        'SELECT * FROM doctors, patients, admins, apiusers, pharmacies, pharmaceutical_companies WHERE id = ? OR SSN = ?',
        [userId, userId],
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Internal Server Error' });
            res.status(200).json(results);
        }
    );
});

// List of all users by gender (secure endpoint)
app.get('/users/gender/:gender', authenticateToken, (req, res) => {
    const user = req.session.user;

    if (!user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const userGender = req.params.gender;

    const query = 'SELECT * FROM doctors WHERE gender = ?';

    connection.query(query, [userGender, userGender, userGender, userGender, userGender], (err, results) => {
        if (err) return res.status(500).json({ message: 'Internal Server Error' });
        res.status(200).json(results);
    });
});




// List of all products/ items (insecure endpoint)
app.get('/drugs', (req, res) => {
    connection.query(
        'SELECT * FROM drugs',
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Internal Server Error' });
            res.status(200).json(results);
        }
    );
});

// Drug information by id (insecure endpoint)
app.get('/drugs/:id', (req, res) => {
    const drugId = req.params.id;

    connection.query(
        'SELECT * FROM drugs WHERE id = ?',
        [drugId],
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Internal Server Error' });
            res.status(200).json(results);
        }
    );
});

// List of all drugs by category/ subcategory (insecure endpoint)
app.get('/drugs/category/:category', (req, res) => {
    const category = req.params.category;

    connection.query(
        'SELECT * FROM drugs WHERE formula = ?',
        [category],
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Internal Server Error' });
            res.status(200).json(results);
        }
    );
});

// ... (add similar routes for other drug-related queries)

// List of drugs by a user (secure endpoint)
app.get('/drugs/user/:userId', authenticateToken, (req, res) => {
    const user = req.session.user;

    if (!user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const userId = req.params.userId;

    // Add logic to get drugs purchased by the user
    // Replace the following query with the actual logic based on your database structure
    connection.query(
        'SELECT * FROM prescriptions WHERE patient_ssn = ?',
        [userId],
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Internal Server Error' });
            res.status(200).json(results);
        }
    );
});


//Access data without authentication

app.post('/token',(req,res)=>{
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err,user)=>{
        if(err) return res.sendStatus(403)
        const accessToken = generateAccessToken({name : user.name})
        res.json({accessToken : accessToken})

    })
})

app.delete('/logout',(req,res)=>{
    refreshTokens = refreshTokens.filter(token => token!=req.body.token)
    res.sendStatus(204)
})