const { clone } = require('../core/util');
const jsonpath = require('jsonpath');

function setDeep(obj, path, value) {
    const keys = path.split('.');
    const last = keys.pop();
    let current = obj;
    for (const key of keys) {
        if (!current[key] || typeof current[key] !== 'object') {
            current[key] = {};
        }
        current = current[key];
    }
    current[last] = value;
}

exports.construct = async function(options) {
    // 1. Initialize: Empty object OR Clone of provided data
    let contextObject = {};
    if (options.data) {
        contextObject = clone(this.parse(options.data));
    }

    // 2. Execute steps within the scope of this object
    if (options.steps) {
        await this.withScope(contextObject, async () => {
            await this._exec(options.steps);
        });
    }

    return contextObject;
};

exports.set = function(options) {
    let key = this.parseRequired(options.key, 'string', 'object.set: key is required.');
    let value = this.parse(options.value);

    if (key.includes('.')) {
        setDeep(this.scope.data, key, value);
    } else {
        this.scope.data[key] = value;
    }
};

exports.remove = function(options) {
    let key = this.parseRequired(options.key, 'string', 'object.remove: key is required.');
    // Note: Simple remove. For deep remove, we might need a helper or use 'set' with undefined.
    delete this.scope.data[key];
};

exports.merge = function(options) {
    let data = this.parse(options.data);
    if (data && typeof data == 'object') {
        Object.assign(this.scope.data, data);
    }
};

exports.query = function(options) {
    let expression = this.parseRequired(options.expression, 'string', 'object.query: expression is required.');
    // Query the current context object (this.scope.data)
    // Returns array of matches
    return jsonpath.query(this.scope.data, expression);
};
