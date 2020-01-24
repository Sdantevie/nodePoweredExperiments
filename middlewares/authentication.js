'use strict';
const jwt = require('jsonwebtoken');
const secretKey = require(__dirname + '/../config/config.json')['jwtSecretKey'];


const verifyToken = (req, res, next) => {
    let token = req.headers['x-access-token'];
    if(!token){
        return res.status(401).send({auth: false, message: "No token provided"});
    }
    jwt.verify(token, secretKey, (err, payload) => {
        if(err){
            return res.status(500).send({auth: false, message: "Failed to authenticate"});
        }

        req.UserId = payload.id;
        next();
    });

}

module.exports = {
    'verifyToken': verifyToken
};