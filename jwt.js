/*
 * jwt-simple
 *
 * JSON Web Token encode and decode module for node.js
 *
 * Copyright(c) 2011 Kazuhito Hokamura
 * MIT Licensed
 */

/**
 * Module dependencies.
 */
const crypto = require('crypto');
const timespan = require('./timespan');

/**
 * Support algorithm mapping.
 */
const algorithmMap = {
	HS256: 'sha256',
	HS384: 'sha384',
	HS512: 'sha512',
	RS256: 'RSA-SHA256',
};

/**
 * Map algorithm to hmac or sign type, to determine which crypto function to use.
 */
const typeMap = {
	HS256: 'hmac',
	HS384: 'hmac',
	HS512: 'hmac',
	RS256: 'sign',
};


const options_to_payload = {
	audience: 'aud',
	issuer:   'iss',
	subject:  'sub',
	jwtid:    'jti',
};

const options_for_objects = [
	'expiresIn',
	'notBefore',
	'noTimestamp',
	'audience',
	'issuer',
	'subject',
	'jwtid',
];

/**
 * Expose object.
 */
const jwt = module.exports;


/**
 * Version.
 */
jwt.version = '0.5.6';

/**
 * Decode jwt.
 *
 * @param {object} token
 * @param {string} key
 * @param {boolean} [noVerify]
 * @param {string} [algorithm]
 * @returns {object} Payload.
 * @api public
 */
jwt.decode = function jwt_decode(token, key, noVerify, algorithm) {
	// check token
	if (!token) {
		throw new Error('No token supplied');
	}
	// check segments
	const segments = token.split('.');
	if (segments.length !== 3) {
		throw new Error('Not enough or too many segments');
	}

	// All segment should be base64
	const headerSeg = segments[0];
	const payloadSeg = segments[1];
	const signatureSeg = segments[2];

	// base64 decode and parse JSON
	const header = JSON.parse(base64urlDecode(headerSeg));
	const payload = JSON.parse(base64urlDecode(payloadSeg));

	if (!noVerify) {
		if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
			algorithm = 'RS256';
		}

		const signingMethod = algorithmMap[algorithm || header.alg];
		const signingType = typeMap[algorithm || header.alg];
		if (!signingMethod || !signingType) {
			throw new Error('Algorithm not supported');
		}

		// verify signature. `sign` will return base64 string.
		const signingInput = [ headerSeg, payloadSeg ].join('.');
		if (!verify(signingInput, key, signingMethod, signingType, signatureSeg)) {
			throw new Error('Signature verification failed');
		}

		// Support for nbf and exp claims.
		// According to the RFC, they should be in seconds.
		if (payload.nbf && Date.now() < payload.nbf * 1000) {
			throw new Error('Token not yet active');
		}

		if (payload.exp && Date.now() > payload.exp * 1000) {
			throw new Error('Token expired');
		}
	}

	return payload;
};


/**
 * Encode jwt.
 *
 * @param {object} payload
 * @param {string} key
 * @param {string} algorithm
 * @param callback
 * @param secretOrPrivateKey
 * @param {object} options
 * @returns {string} Token.
 * @api public
 */
jwt.sign = function jwt_encode(payload, secretOrPrivateKey, { algorithm = 'HS256', expiresIn, notBefore, audience, issuer, jwtid, subject, noTimestamp, header, keyid } = {}, callback) {

	const options = { algorithm, expiresIn, notBefore, audience, issuer, jwtid, subject, noTimestamp, header, keyid };

	// DEBUG: options
	console.debug(`🦠  options: ${JSON.stringify(options, null, 2)}`);

	// Check key
	if (!secretOrPrivateKey) {
		throw new Error('Require key');
	}

	const signingMethod = algorithmMap[options.algorithm];
	const signingType = typeMap[options.algorithm];
	if (!signingMethod || !signingType) {
		throw new Error('Algorithm not supported');
	}
	const isObjectPayload = typeof payload === 'object'
	&& !Buffer.isBuffer(payload);

	header = Object.assign({
		alg: options.algorithm || 'HS256',
		typ: isObjectPayload ? 'JWT' : undefined,
		kid: keyid,
	 }, header);

	 function failure(err) {
		if (callback) {
		  return callback(err);
		}
		throw err;
	 }

	 if (!secretOrPrivateKey && options.algorithm !== 'none') {
		return failure(new Error('secretOrPrivateKey must have a value'));
	 }

	 if (typeof payload.exp !== 'undefined' && typeof options.expiresIn !== 'undefined') {
		return failure(new Error('Bad "expiresIn" option the payload already has an "exp" property.'));
	 }

	 if (typeof payload.nbf !== 'undefined' && typeof options.notBefore !== 'undefined') {
		return failure(new Error('Bad "notBefore" option the payload already has an "nbf" property.'));
	 }

	 const timestamp = payload.iat || Math.floor(Date.now() / 1000);

	 if (noTimestamp) {
		delete payload.iat;
	 } else if (isObjectPayload) {
		payload.iat = timestamp;
	 }

	 if (typeof notBefore !== 'undefined') {
		try {
		  payload.nbf = timespan(notBefore, timestamp);
		} catch (err) {
		  return failure(err);
		}
		if (typeof payload.nbf === 'undefined') {
		  return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
		}
	 }

	 if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
		try {
		  payload.exp = timespan(options.expiresIn, timestamp);
		} catch (err) {
		  return failure(err);
		}
		if (typeof payload.exp === 'undefined') {
		  return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
		}
	 }

	 Object.keys(options_to_payload).forEach(key => {
		const claim = options_to_payload[key];
		if (typeof options[key] !== 'undefined') {
		  if (typeof payload[claim] !== 'undefined') {
			 return failure(new Error(`Bad "options.${key}" option. The payload already has an "${claim}" property.`));
		  }
		  payload[claim] = options[key];
		}
	 });

	// create segments, all segments should be base64 string
	const segments = [];
	segments.push(base64urlEncode(JSON.stringify(header)));
	segments.push(base64urlEncode(JSON.stringify(payload)));
	segments.push(sign(segments.join('.'), secretOrPrivateKey, signingMethod, signingType));

	return segments.join('.');
};

/**
 * Private util functions.
 */

// function assignProperties(dest, source) {
// 	for (const attr in source) {
// 		if (source.hasOwnProperty(attr)) {
// 			dest[attr] = source[attr];
// 		}
// 	}
// }

function verify(input, key, method, type, signature) {
	if (type === 'hmac') {
		return (signature === sign(input, key, method, type));
	} else if (type === 'sign') {
		return crypto.createVerify(method)
			.update(input)
			.verify(key, base64urlUnescape(signature), 'base64');
	} else {
		throw new Error('Algorithm type not recognized');
	}
}

function sign(input, key, method, type) {
	let base64str;
	if (type === 'hmac') {
		base64str = crypto.createHmac(method, key).update(input).digest('base64');
	} else if (type === 'sign') {
		base64str = crypto.createSign(method).update(input).sign(key, 'base64');
	} else {
		throw new Error('Algorithm type not recognized');
	}

	return base64urlEscape(base64str);
}

function base64urlDecode(str) {
	return Buffer.from(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape(str) {
	str += new Array(5 - str.length % 4).join('=');
	return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function base64urlEncode(str) {
	return base64urlEscape(Buffer.from(str).toString('base64'));
}

function base64urlEscape(str) {
	return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]/g, '');
}
