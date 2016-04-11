var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

// 1) add dependencies for password recovery

var session = require('express-session');
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var async = require('async');
var bcrypt = require('bcrypt-nodejs');
//part of express library
var crypto = require('crypto');


var app = express();

// 7) set up local strategy?

passport.use(new LocalStrategy(function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect username.' });
        user.comparePassword(password, function(err, isMatch) {
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Incorrect password.' });
            }
        });
    });
}));

//8) serialize and deserialize

passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});


// 3) create user model with a Schema
var userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});


// 4) use bcrypt to hash the password

userSchema.pre('save', function (next) {
    var user = this;
    var SALT_FACTOR = 5;

    if (!user.isModified('password')) return next();

    bcrypt.genSalt(SALT_FACTOR, function (err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, null, function (err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

// 5) password verification

userSchema.methods.comparePassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch){
        if (err) return cb(er);
        cb(null, isMatch);
    });
};

// 6) use the User model
var User = mongoose.model('User', userSchema);


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


// 2) passport config section

app.use(session({
    secret: 'sawyerisacorgi',
    resave: true,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


//routes (keep all routes?)
app.get('/', function (req, res, next) {
    res.render('index', {
        title: 'Comp2106 Forgot Password Tutorial by Adam, Kayley, Mackenzie and Michele'
    });
});


//add login (keep)
app.get('/login', function(req, res, next){
    res.render('login',{
        title: 'Login',
        user: req.user
    });
});

app.post('/login', function(req, res, next){
   passport.authenticate('local', function(err, user, info) {
      if (err) return next(err)
       if (!user) {
           return res.redirect('/login')
       }
       req.logIn(user, function(err){
          if (err) return next(err);
           return res.redirect('/');
       });
   })(req, res, next);
});

//sign up
app.get('signup', function(req, res, next){
    res.render('signup', {
        title: 'Register',
        user: req.user
    });
});


// db connection (keep)
var db = mongoose.connection;

db.on('error', console.error.bind(console, 'DB Error: '));

db.once('open', function (callback) {
    console.log('Connected to mongodb');
});


// read db connection string from our config file
var configDb = require('./config/db.js');
mongoose.connect(configDb.url);


module.exports = app;
