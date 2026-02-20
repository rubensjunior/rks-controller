const AuthProvider = require('./provider');
const debug = require('debug')('server-connect:auth');

class SingleProvider extends AuthProvider {

    constructor(app, opts, name) {
        super(app, opts, name);
        this.username = opts.username;
        this.password = opts.password;
    }

    getIdentity(username) {
        if (username == this.username) {
            return this.username;
        }
        return false;
    }

    getUsername(identity) {
        if (identity == this.username) {
            return this.username;
        }
        return null;
    }

    validate(username, password) {
        if (username == this.username && password == this.password) {
            return username;
        }

        return false;
    }

    permissions() {
        return true;
    }

}

module.exports = SingleProvider;