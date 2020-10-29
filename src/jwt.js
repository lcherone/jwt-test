const debug = require("debug")("app:jwt");

const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

module.exports = options =>
  new function(options) {
    this.certsPath = options.certsPath || ".";
    this.options = {
      algorithm: "RS256",
      keyid: "1",
      noTimestamp: false,
      expiresIn: "3600s"
    };

    const privateKey = fs.readFileSync(
      path.join(this.certsPath, "private.key")
    );
    const publicKey = fs.readFileSync(path.join(this.certsPath, "public.pem"));

    var JWT = this;

    JWT.sign = function(payload, options) {
      options = Object.assign({}, this.options, options || {});
      debug("[sign] payload: %o\n[sign] options: %o", payload, options);

      return jwt.sign(payload, privateKey, options);
    };

    JWT.refresh = function(token, options) {
      options = Object.assign({}, this.options, options || {});
      debug(
        "[refresh] token: %o\n[refresh] options: %o",
        token.substr(0, 32) + "...",
        options
      );

      // at this point we know token is valid but expired
      let payload = {};
      try {
        // better
        payload = jwt.verify(token, publicKey);
      } catch (err) {
        // fallback to just decode
        payload = JWT.decode(token);
      }

      payload = payload.payload;

      // remove what we dont want
      delete payload.iat;
      delete payload.exp;
      delete payload.nbf;
      delete payload.jti;

      debug("[refresh] Old token payload:", payload);
      const newToken = jwt.sign(
        payload,
        privateKey,
        Object.assign({}, this.options, { jwtid: options.jwtid || "1" })
      );
      debug("[refresh] New token payload:", JWT.decode(newToken));

      return newToken;
    };

    JWT.verify = function(token, options) {
      options = options || { verify: {} };
      debug("[verify]", token, options);

      return jwt.verify(token, publicKey, options.verify);
    };

    JWT.decode = function(token) {
      debug("[decode]", token);

      return jwt.decode(token, { complete: true });
    };

    return JWT;
  }(options);
