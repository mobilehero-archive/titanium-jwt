// const jsonwebtoken = require('@titanium/jwt');
const jsonwebtoken = require('./jwt');
const _ = require('lodash');
const moment = require('moment');
// const logger = require('@geek/logger');

class AuthToken {
	constructor(data, params = {}) {
		console.debug('🔒  you are here →   AuthToken.constructor');
		this.token_type = data.token_type && data.token_type.toLowerCase();
		this.access_token = data.access_token;
		this.refresh_token = data.refresh_token;
		this.parseExpiresIn(Number(data.expires_in));
		this.raw = _.omit(data, [ 'token_type', 'access_token', 'refresh_token', 'expires_in' ]);


		this.access_token_jwt = jsonwebtoken.decode(this.access_token, params.key);
		this.refresh_token_jwt = jsonwebtoken.decode(this.refresh_token, null, true);
		// console.debug(`this.jwt: ${JSON.stringify(this.jwt, null, 2)}`);

		if (this.access_token_jwt) {

			this.authenticated = true;
			this.user = {
				username:       this.access_token_jwt.username || this.access_token_jwt.preferred_username,
				first_name:     this.access_token_jwt.given_name,
				last_name:      this.access_token_jwt.family_name,
				formatted_name: this.access_token_jwt.name,
				email:          this.access_token_jwt.email,
				scopes:         _.split(_.trim(this.access_token_jwt.scope || ''), /\s+/g).filter(o => o),
			};
			this.issuer = this.access_token_jwt.iss;
			this.audience = this.access_token_jwt.aud;
			this.subject = this.access_token_jwt.sub;

			// this.access_token_issued_at = moment.unix(this.access_token_jwt.iat);
			// this.access_token_expires_at = moment.unix(this.access_token_jwt.exp);

		}

		this.expiresIn = () => this.expires_at.fromNow();

	}

	parseExpiresIn(duration) {
		console.debug('🦖  you are here →   token.parseExpiresIn');
		if (typeof duration === 'number') {
		  this.expires_at = new Date();
		  this.expires_at.setSeconds(this.expires_at.getSeconds() + duration);
		} else if (duration instanceof Date) {
		  this.expires_at = new Date(duration.getTime());
		} else {
		  throw new TypeError(`Unknown duration: ${duration}`);
		}

		return moment(this.expires_at);
	  }


	  isExpired() {
		return Date.now() > this.expires.getTime();
	  }


}

module.exports = AuthToken;
