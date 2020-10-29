process.env.DEBUG = "app:*";

const debug = require("debug")("app:index");
const path = require("path");
const certsPath = path.join(__dirname, "..", "certs");

const JWT = require("./jwt")({
  certsPath
});

debug("\nJWT wrapper:\n%O", JWT);

const NOW = Math.floor(Date.now() / 1000);
let TEST_SUCCESS = true;

function test_valid() {
  debug(
    "\n[test for valid]\n - Runs a test that will check a valid token can be created,\n   with no changes to options."
  );

  // set options (this is the default)
  let options = {
    algorithm: "RS256",
    keyid: "1",
    noTimestamp: false,
    expiresIn: "60s"
  };
  debug("\noptions:\n%O", options);

  // payload
  let payload = {
    id: 12345,
    role: "user",
    foo: "barbaz",
    iat: Math.floor(Date.now() / 1000) - 30 // backdate so 30 seconds left (for testing)
  };
  debug("payload:%O", payload);

  /**
   * Create token
   */
  let token = JWT.sign(payload, options);
  debug("\nJWT.sign(%O, %O)\nNew Token:", payload, options, token);

  /**
   * Decode token (to test for the 1 second)
   */
  let decoded = JWT.decode(token);
  debug("\nJWT.decode(%s)\nDecoded Token: %O\n", token, decoded);

  // check expiry
  debug("\nIssued at check:");
  debug(" - Its now: " + NOW);
  debug(" - Tokens are set to expire after: ", options.expiresIn);
  debug(
    " - We backdated the token 30s to " +
      payload.iat +
      (decoded.payload.iat === payload.iat
        ? " (successfully signed and decoded)"
        : " (failed to sign and decode)")
  );
  debug(" - So token will expire in: " + (decoded.payload.exp - NOW) + "s");

  /**
   * Verify token
   */
  try {
    decoded = JWT.verify(token);
    debug("\nVerify token [sync]: success\n", decoded);
  } catch (e) {
    TEST_SUCCESS = false;
    debug("\nVerify token [sync]: failed\n", e);
  }
}
test_valid();

function test_expired() {
  debug(
    "\n[test for expired]\n - Runs a test that will create a valid token but expired."
  );

  // set options (this is the default)
  let options = {
    algorithm: "RS256",
    keyid: "1",
    noTimestamp: false,
    expiresIn: "60s"
  };
  debug("\noptions:\n%O", options);

  // payload
  let payload = {
    id: 12345,
    role: "user",
    foo: "barbaz",
    iat: Math.floor(Date.now() / 1000) - 120 // backdate 2 mins so is expired
  };
  debug("payload:%O", payload);

  /**
   * Create token
   */
  let token = JWT.sign(payload, options);
  debug("\nJWT.sign(%O, %O)\nNew Token:", payload, options, token);

  /**
   * Decode token (to test for the 1 second)
   */
  let decoded = JWT.decode(token);
  debug("\nJWT.decode(%s)\nDecoded Token: %O\n", token, decoded);

  // check expiry
  debug("\nIssued at check:");
  debug(" - Its now: " + NOW);
  debug(" - Tokens are set to expire after: ", options.expiresIn);
  debug(
    " - We backdated the token 120s to " +
      payload.iat +
      (decoded.payload.iat === payload.iat
        ? " (successfully signed and decoded)"
        : " (failed to sign and decode)")
  );
  debug(" - So token will expire in: " + (decoded.payload.exp - NOW) + "s");

  /**
   * Verify token
   */
  try {
    decoded = JWT.verify(token);

    debug("\nVerify token [sync]: success");
    debug(" - Test failed as token should not be valid");
    TEST_SUCCESS = false;
  } catch (e) {
    // it should have failed, lets check for error
    if (e.name === "TokenExpiredError") {
      debug("\nVerify token [sync]: success");
      debug(" - Test success: " + e.message);
    } else {
      TEST_SUCCESS = false;
      debug(" - Test failed not expecting", e);
    }
  }
}
test_expired();

function test_empty() {
  debug("\n[test for empty]\n - Runs a test that will handle empty token");

  // set options (this is the default)
  let options = {
    algorithm: "RS256",
    keyid: "1",
    noTimestamp: false,
    expiresIn: "60s"
  };
  debug("\noptions:\n%O", options);

  /**
   * Decode token empty token
   */
  let decoded = JWT.decode("");
  debug("Decoded Token: %O\n", decoded);

  // check

  /**
   * Verify token
   */
  var token = "";
  try {
    decoded = JWT.verify(token);

    debug("\nVerify token [sync]: success");
    debug(" - Test failed as token should not be valid");
    TEST_SUCCESS = false;
  } catch (e) {
    //
    if (e.name === "JsonWebTokenError") {
      debug("\nVerify token [sync]: success");
      debug(" - Test success: " + e.message);
    } else {
      debug(" - Test failed not expecting", e);
      TEST_SUCCESS = false;
    }
  }
}
test_empty();

function test_tampered_expired() {
  debug(
    "\n[test for tampered]\n - Runs a test that will check a tampered token (last letter X should be Q) can be verify,\n   with no changes to options."
  );

  let expired_token =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZC" +
    "I6IjEifQ.eyJpZCI6MTIzNDUsInJvbGUiOiJ1c2VyI" +
    "iwiZm9vIjoiYmFyYmF6IiwiaWF0IjoxNTQ5NDQwNzU" +
    "3LCJleHAiOjE1NDk0NDA4MTd9.lxTRfJ2J8mXHLWoq" +
    "PIgwykpkbHp3f_Z4J1-OvY0JQSj2ZkPm1xvrpBtu7X" +
    "NLEQpJItXVK4ZhFQmUZROwLd4czhBKxIXQdcMD98O5" +
    "x60YW0kjt6P_EjBgHmi9YOHJUsCbg0dQjgC7dM28-U" +
    "GLjfRNc7_GUFXnc7CenLTFwkIooux_9qJJqfov0Mkl" +
    "F9bMvDk9CQ757eun0JZSs_eqTs48PkBQgEQusi8Bc3" +
    "uAEn_d02rVx0axJS9Gm8n59JDRdODL4LNOYGZAZDW0" +
    "xcx_6wulxkudfQkYZKiF5kOZQObK60vMc1eVww7S3a" +
    "JGduLvps1byqvC-j43fBzLjIwCtD9JlX"; // < last letter X should be Q

  // set options (this is the default)
  let options = {
    algorithm: "RS256",
    keyid: "1",
    noTimestamp: false,
    expiresIn: "60s"
  };
  debug("\noptions:\n%O", options);

  // payload
  let payload = {
    id: 12345,
    role: "user",
    foo: "barbaz"
  };
  debug("payload:%O", payload);

  /**
   * Decode expired_token, only signiture was tampered
   */
  let decoded = JWT.decode(expired_token);
  debug("\nJWT.decode(%s)\nDecoded Token: %O\n", expired_token, decoded);

  /**
   * Verify token
   */
  try {
    debug(
      "\nVerify token [sync]: testing for expired token because only signiture was tampered"
    );
    decoded = JWT.verify(expired_token);

    debug("\nVerify token [sync]: success");
    debug(" - Test failed as token should not be valid");
    TEST_SUCCESS = false;
  } catch (e) {
    //
    if (e.name === "JsonWebTokenError") {
      debug("\nVerify token [sync]: success");
      debug(" - Test success, expecting: " + e.message);
    } else {
      debug(" - Test failed not expecting: ", e.name);
      TEST_SUCCESS = false;
    }
  }
}
test_tampered_expired();

function test_tampered_signiture() {
  debug(
    "\n[test for tampered]\n - Runs a test that will check a tampered token (first letter X should be e) can be verify,\n   with no changes to options."
  );

  let expired_token =
    // First letter X should be e
    "XyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZC" +
    "I6IjEifQ.eyJpZCI6MTIzNDUsInJvbGUiOiJ1c2VyI" +
    "iwiZm9vIjoiYmFyYmF6IiwiaWF0IjoxNTQ5NDQwNzU" +
    "3LCJleHAiOjE1NDk0NDA4MTd9.lxTRfJ2J8mXHLWoq" +
    "PIgwykpkbHp3f_Z4J1-OvY0JQSj2ZkPm1xvrpBtu7X" +
    "NLEQpJItXVK4ZhFQmUZROwLd4czhBKxIXQdcMD98O5" +
    "x60YW0kjt6P_EjBgHmi9YOHJUsCbg0dQjgC7dM28-U" +
    "GLjfRNc7_GUFXnc7CenLTFwkIooux_9qJJqfov0Mkl" +
    "F9bMvDk9CQ757eun0JZSs_eqTs48PkBQgEQusi8Bc3" +
    "uAEn_d02rVx0axJS9Gm8n59JDRdODL4LNOYGZAZDW0" +
    "xcx_6wulxkudfQkYZKiF5kOZQObK60vMc1eVww7S3a" +
    "JGduLvps1byqvC-j43fBzLjIwCtD9JlQ";

  // set options (this is the default)
  let options = {
    algorithm: "RS256",
    keyid: "1",
    noTimestamp: false,
    expiresIn: "60s"
  };
  debug("\noptions:\n%O", options);

  // payload
  let payload = {
    id: 12345,
    role: "user",
    foo: "barbaz"
  };
  debug("payload:%O", payload);

  /**
   * Decode expired_token, only signiture was tampered
   */
  let decoded = JWT.decode(expired_token);
  debug("\nJWT.decode(%s)\nDecoded Token: %O\n", expired_token, decoded);

  /**
   * Verify token
   */
  try {
    debug(
      "\nVerify token [sync]: testing for invalid token because payload was tampered"
    );
    decoded = JWT.verify(expired_token);

    debug("\nVerify token [sync]: success");
    debug(" - Test failed as token should not be valid");
    TEST_SUCCESS = false;
  } catch (e) {
    //
    if (e.name === "JsonWebTokenError") {
      debug("\nVerify token [sync]: success");
      debug(" - Test success, expecting: " + e.message);
    } else {
      debug(" - Test failed not expecting: ", e);
      TEST_SUCCESS = false;
    }
  }
}
test_tampered_signiture();

// @todo: refresh

debug(TEST_SUCCESS ? "\nAll test passed" : "\nSome tests failed");
