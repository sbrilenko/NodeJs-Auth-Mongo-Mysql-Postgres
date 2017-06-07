var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var configDB = require('./../database.js');
var path = require('path');
var Sequelize = require('sequelize');

var sequelize = new Sequelize(configDB[configDB.db].database, configDB[configDB.db].user, configDB[configDB.db].password, {
  host: configDB[configDB.db].host,
  dialect: configDB.db,
  pool: {
    max: 5,
    min: 0,
    idle: 10000
  },
});
var db = configDB.db;
if(db == "postgres") db = "mysql";
var modelsPath = path.join(__dirname, '..','..','models',db);
var models = require('sequelize-import')(modelsPath, sequelize, {
  exclude: []
});
sequelize.authenticate().then(() => {
    console.log('Connection has been established successfully.');
})
.catch(err => {
    console.error('Unable to connect to the database:', err);
});
//sync the model with the database
models.user.sync({ force: true }).then(() => {
});

var configAuth = require('./../auth');

module.exports = function(passport) {

  passport.serializeUser(function(user, done) {
    console.log("serializeUser ",user)
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
      models.user.findById(id).then(user=>{
          done(null, user);
    });
  });

  passport.use('local-signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true,
  },
  function(req, email, password, done) {
    process.nextTick(function() {
        models.user.findOne({ where: {localemail: email } })
            .then(project => {
          if(project){
            return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
          }else{
            models.user.create({
              localemail: email,
              localpass: models.user.generateHash(password)
            }).then(newUser=>{
                console.log(newUser.dataValues.id);
                return done(null, newUser);
            });
          }}
        )
    });
  }));

  passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true,
  },
  function(req, email, password, done) {
      console.log("local-login", email, password)
    models.user.findOne({ where: {localemail: email } })
      .then(project => {
          if(project) { return done(null, project);}
          else if(project && !project.validPassword(password)){
            return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
          }
          else{
            return done(null, false, req.flash('loginMessage', 'No user found.'));
          }
      }).catch(err=>{
            return done(err);
      });
  }));

  passport.use(new FacebookStrategy({
    clientID: configAuth.facebookAuth.clientID,
    clientSecret: configAuth.facebookAuth.clientSecret,
    callbackURL: configAuth.facebookAuth.callbackURL,
    profileFields: ['id', 'email', 'first_name', 'last_name'],
  },
  function(token, refreshToken, profile, done) {
    process.nextTick(function() {
        models.user.findOne({where: { 'facebookid': profile.id }})
        .then(user=>{
            if(user) {
                return done(null, user);
            } else {
                models.user.create({
                    facebookid: profile.id,
                    facebooktoken: token,
                    facebookname: profile.name.givenName + ' ' + profile.name.familyName,
                    facebookemail: (profile.emails[0].value || '').toLowerCase()
                }).then(newUser=>{
                    return done(null, newUser);
                });
            }
        }).catch(err=>{
            return done(err);
        })
    });
  }));

  passport.use(new TwitterStrategy({
    consumerKey: configAuth.twitterAuth.consumerKey,
    consumerSecret: configAuth.twitterAuth.consumerSecret,
    callbackURL: configAuth.twitterAuth.callbackURL,
  },
  function(token, tokenSecret, profile, done) {
    process.nextTick(function() {
      models.user.findOne({where:{ 'twitterid': profile.id }})
      .then(user=>{
        if(user) return done(null, user);
        else {
            models.user.create({
                twitterid          : profile.id,
                twittertoken       : token,
                twitterusername    : profile.username,
                twitterdisplayName : profile.displayName,
            }).then(newUser=>{
                return done(null, newUser);
            });
        }
      }).catch(err=>{
        return done(err);
      })
    });
  }));

  passport.use(new GoogleStrategy({
    clientID: configAuth.googleAuth.clientID,
    clientSecret: configAuth.googleAuth.clientSecret,
    callbackURL: configAuth.googleAuth.callbackURL,
  },
    function(token, refreshToken, profile, done) {
      process.nextTick(function() {
      models.user.findOne({where:{ 'googleid': profile.id }})
          .then(user=>{
              if (user) {
                  return done(null, user);
              } else {
                  models.user.create({
                      googleid : profile.id,
                      googletoken : token,
                      googlename : profile.displayName,
                      googleemail : profile.emails[0].value,
                  }).then(newUser=>{
                      return done(null, newUser);
                  });
              }
          }).catch(err=>{
              return done(err);
          })
      });
    }));

};
