// const BearerStrategy = require('passport-http-bearer').Strategy;
// const HybridStrategy = require('passport-jwt').Strategy;

// Required modules and libraries
const bcrypt = require('bcrypt'); // For hashing and comparing passwords
const db = require('knex')(require('../knexfile')); // Database connection using Knex
const jwt = require('jsonwebtoken');  // For generating and verifying JSON Web Tokens
const session = require('express-session');  // For managing user sessions
const { v4: uuidv4 } = require('uuid');   // For generating unique identifiers
const KnexSessionStore = require('connect-session-knex')(session); // Session store for Knex

const logger = require('./logger');   // Custom logger for logging messages

// Cookie settings for the session
const cookieSettings = {
  httpOnly: true,  // Cookie is only accessible by the server
  secure: false,    // Cookie is sent over HTTP (not HTTPS)
  maxAge: 24 * 60 * 60 * 1000,  // Cookie expires after 24 hours
};

// const convert = (from, to) => (str) => Buffer.from(str, from).toString(to);
class AuthMiddleware {
  // Session manager configuration
  static sessionManager = session({
    cookie: cookieSettings, // Apply the cookie settings
    genid() {
      return uuidv4();   // Generate a unique session ID using UUID
    },
    name: 'refreshToken',  // Name of the session cookie
    resave: false,   // Don't save session if unmodified
    rolling: true,   // Force a session identifier cookie to be set on every response
    saveUninitialized: true,  // Save uninitialized sessions
    secret: process.env.JWT_SIGNING_SECRET,   // Secret key for signing the session ID cookie
    store: new KnexSessionStore({ knex: db }),  // Use Knex as the session store
  });
 
  // JWT configurations
  static signingSecret = process.env.JWT_SECRET; // Secret key for signing JWTs

  static accessTokenExpirationTime = process.env.JWT_EXPIRATION_TIME;   // Expiration time for access tokens
  
  // Create a new session for the user
  static async newSession(payload, req, res, checkDB = true) {
    let users = [payload];

    // We don't want to hit the DB again if we just created this user.
    if (checkDB) {
      users = await db.from('users').where('users.uid', payload.uid);
      if (users.length < 1) {
        res
          .status(403)
          .json({
            error: 'User not found',
            user: null,
          })
          .send();
        return false;
      }
    } else if (!payload.uid) {
      res
        .status(403)
        .json({
          error: 'Invalid user info',
          user: null,
        })
        .send(); // TODO - throw an error here and catch when
      return false; //        calling since this isn't really a
    } //                      "client" issue / 403

    try {
      const user = {
        uid: users[0].uid,
        email: users[0].email,
        first_name: users[0].first_name,
        last_name: users[0].last_name,
        preferences: users[0].preferences,
      };

      // Remove old sessions - our rolling sessions should have created a new one
      AuthMiddleware.destroyOldSessionsForUser(user.uid, req.sessionID);

      // Create the access token and attach it to the response.
      const accessToken = await jwt.sign(user, AuthMiddleware.signingSecret, {
        expiresIn: AuthMiddleware.accessTokenExpirationTime,
      });
      req.session.accessToken = accessToken;
      req.session.currentAccessToken = accessToken;
      req.session.save();
      res.cookie('accessToken', accessToken, cookieSettings);
      // Return the user on success
      return user;
    } catch (error) {
      res
        .status(500)
        .json({
          user: null,
        })
        .send();
      logger.log('warn', `Error: ${error}`);
      return false;
    }
  }
 
  // Destroy old sessions for a specific user
  static async destroyOldSessionsForUser(userUID, currentID) {
    db.from('sessions')
      .where('sessions.user_uid', userUID)
      .whereNot('sid', currentID)
      .del();
  }

  // Extract JWT from request cookies
  static jwtFromRequest(req) {
    let token = null;
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    return token;
  }
  
  // Authenticate using JWT or session
  static authenticateHybrid(req, res, next) {
    if (!req.locals) {
      // CTODO - move this to a middleware
      req.locals = {};
    }

    const token = AuthMiddleware.jwtFromRequest(req);

    if (!token) {
      return res
        .status(403)
        .json({
          user: null,
        })
        .send();
    }

    // Verify the JWT (AccessToken) or the session (RefreshToken)
    jwt.verify(token, AuthMiddleware.signingSecret, (jwtError1, payload) => {
      if (jwtError1) {
        if (jwtError1 instanceof jwt.TokenExpiredError) {
          jwt.verify(
            token,
            AuthMiddleware.signingSecret,
            { ignoreExpiration: true },
            (jwtError2, secondPayload) => {
              if (jwtError2) {
                res
                  .status(403)
                  .json({
                    user: null,
                  })
                  .send();
              } else {
                AuthMiddleware.sessionManager(req, res, () => {
                  if (req.session && req.session.currentAccessToken === token) {
                    // Valid refresh token but expired access token - refresh
                    //   them both with a new session
                    AuthMiddleware.newSession(
                      secondPayload,
                      req,
                      res,
                      true,
                    ).then((user) => {
                      if (user) {
                        req.locals.user = user;
                      } // what if else?
                      next();
                    });
                  } else {
                    // It looks like a token was stolen - Ivalidate all sessions for user in jwt
                    AuthMiddleware.destroyOldSessionsForUser(
                      secondPayload.uid,
                      '',
                    );
                    res
                      .status(403)
                      .json({
                        user: null,
                      })
                      .send();
                  }
                });
              }
            },
          );
        } else {
          res
            .status(403)
            .json({
              user: null,
            })
            .send(); // Invalid session fell through.
        }
      } else {
        req.locals.user = payload;
        next();
      }
    });
  }

  // Extract bearer token from request headers
  static bearerFromRequest(req) {
    let token = null;
    if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return false;
      }
    }
    return token;
  }

  // Authenticate using bearer token without passthrough
  static authenticateBearerWithoutPassthrough(req, res, next) {
    AuthMiddleware.authenticateBearer(req, res, next, false);
  }

  // Authenticate using bearer token with passthrough
  static authenticateBearerWithPassthrough(req, res, next) {
    AuthMiddleware.authenticateBearer(req, res, next, true);
  }
  
  // Authenticate using bearer token
  static authenticateBearer(req, res, next, passthrough = false) {
    if (!req.locals) {
      // CTODO - move this to a middleware
      req.locals = {};
    }

    const token = AuthMiddleware.bearerFromRequest(req);
    if (!token) {
      if (!passthrough) {
        return res.status(403).send();
      }
      return next();
    }

    // CTODO - Should these be JWTs with refresh?
    const strippedPrefix = token.substring(
      token.indexOf('_') + 1,
      token.length,
    );
    const indexPoint = strippedPrefix.indexOf('.');
    const uid = strippedPrefix.substring(0, indexPoint);
    const tokenValue = strippedPrefix.substring(
      indexPoint + 1,
      strippedPrefix.length,
    );

    db.from('access_tokens')
      .where('uid', uid)
      .then(async (tokens) => {
        if (tokens.length === 1) {
          const isMatch = await bcrypt.compare(
            tokenValue,
            tokens[0].access_token_hash,
          );
          if (isMatch) {
            const user = await db('users')
              .where('uid', tokens[0].owner_uid)
              .first(); // TODO: Should be an org and won't handle perms
            if (user) {
              req.locals.user = user;
              next();
            } else {
              return res.status(403).send();
            }
          }
        } else {
          return res.status(403).send();
        }
      })
      .catch((err) => {
        logger.log('info', `Error matching token: ${err}`);
        return res.status(500).send();
      });
  } // CTODO - incorrect token on yatt-pipe just hangs
}

// Export the AuthMiddleware class
module.exports = {
  AuthMiddleware,
}; 
