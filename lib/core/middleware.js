const config = require('../setup/config');
const debug = require('debug')('server-connect:router');
const { clone } = require('./util');
const App = require('./app');

module.exports = {
    cache: function(options) {
        return async function(req, res, next) {
            // Do not cache OPTIONS (CORS preflight) requests
            if (req.method && req.method.toUpperCase() === 'OPTIONS') {
                return next();
            }

            if (!options.ttl || !global.redisClient) {
                // no caching
                return next();
            }

            let key = 'erc:' + (req.originalUrl || req.url);
            let nocache = false;
            let nostore = false;

            if (req.fragment) {
                key += '-fragment';
            }

            if (req.query.nocache) {
                nocache = true;
            }

            try {
                const cacheControl = req.get('Cache-Control');
                if (cacheControl) {
                    if (cacheControl.includes('no-cache')) nocache = true;
                    if (cacheControl.includes('no-store')) nostore = true;
                }
            } catch (err) {
                // Ignore but log errors
                console.error(err);
            }

            if (!nocache) {
                try {
                    const cache = await global.redisClient.hgetall(key);
                    if (cache.body) {
                        res.type(cache.type || 'text/html');
                        res.send(cache.body);
                        return;
                    }
                } catch (err) {
                    // Ignore but log errors
                    console.error(err);
                }
            }

            if (!nostore) {
                // wrap res.send
                const send = res.send.bind(res);
                res.send = function (body) {
                    const ret = send(body);

                    if (this.statusCode !== 200 || typeof body !== 'string') {
                        // do not cache when not status 200 or body is not a string
                        return ret;
                    }

                    global.redisClient.hset(key, {
                        body: body,
                        type: this.get('Content-Type') || 'text/html'
                    }).then(() => {
                        return global.redisClient.expire(key, +options.ttl);
                    }).catch(err => {
                        // Ignore but log errors
                        console.error(err);
                    });

                    return ret;
                };
            }

            return next();
        };
    },

    rateLimiter: function(options) {
        const points = options.points ?? 1;

        return async function(req, res, next) {
            // Do not rate limit OPTIONS (CORS preflight) requests
            if (req.method && req.method.toUpperCase() === 'OPTIONS') {
                return next();
            }

            const app = req.app;

            if (app.rateLimiter && points > 0) {
                let isPrivate = false;
                let key = req.ip;

                if (app.privateRateLimiter) {
                    if (req.session && req.session[config.rateLimit.private.provider + 'Id']) {
                        isPrivate = true;
                        key = req.session[config.rateLimit.private.provider + 'Id'];
                    }
                }

                app[isPrivate ? 'privateRateLimiter' : 'rateLimiter'].consume(key, points).then(rateLimiterRes => {
                    const reset = Math.ceil(rateLimiterRes.msBeforeNext / 1000);
                    const { points: limitPoints, duration } = isPrivate ? config.rateLimit.private : config.rateLimit;

                    res.set('RateLimit-Policy', `${limitPoints};w=${duration}`);
                    res.set('RateLimit', `limit=${limitPoints}, remaining=${rateLimiterRes.remainingPoints}, reset=${reset}`);

                    next();
                }).catch(rateLimiterRes => {
                    const reset = Math.ceil(rateLimiterRes.msBeforeNext / 1000);
                    const { points: limitPoints, duration } = isPrivate ? config.rateLimit.private : config.rateLimit;

                    res.set('RateLimit-Policy', `${limitPoints};w=${duration}`);
                    res.set('RateLimit', `limit=${limitPoints}, remaining=${rateLimiterRes.remainingPoints}, reset=${reset}`);
                    res.set('Retry-After', reset);

                    if (req.is('json')) {
                        res.status(429).json({ error: 'Too Many Requests' });
                    } else {
                        res.status(429).send('Too Many Requests');
                    }
                });
            } else {
                debug(`WARNING: Using rateLimiter middleware without initializing rateLimiter on app.`);
                next();
            }
        };
    },

    csrfProtection: function(options) {
        return (req, res, next) => {
            // Do not apply csrf protection for OPTIONS (CORS preflight) requests
            if (req.method && req.method.toUpperCase() === 'OPTIONS') {
                return next();
            }

            if (config.csrf.exclude.split(',').includes(req.method)) return next();
            if (!req.validateCSRF()) return res.status(403).send('Invalid CSRF token');
            next();
        };
    },

    restrictAccess: function(options) {
        const { provider } = options;

        if (!provider) { throw new TypeError('Restrict middleware requires a security provider'); }

        return async function(req, res, next) {
            const app = new App(req, res);

            await app.exec({
                module: 'auth',
                action: 'restrict',
                options
            }, true);

            if (res.headersSent) {
                // response already sent in restrict
                return;
            }

            next();
        };
    },

    serverConnect: function(json) {
        return async function(req, res, next) {
            const app = new App(req, res);

            debug(`Serving serverConnect ${req.path}`);

            return Promise.resolve(app.define(json)).catch(next);
        };
    },

    templateView: function(layout, page, data, exec) {
        return async function(req, res, next) {
            const app = new App(req, res);

            debug(`Serving templateView ${req.path}`);

            const routeData = clone(data);
            const methods = {
                _: (expr, data = {}) => {
                    return app.parse(`{{${expr}}}`, app.scope.create(data));
                },

                _exec: async (name, steps, data = {}) => {
                    let context = {};
                    app.scope = app.scope.create(data, context);
                    await app.exec(steps, true);
                    app.scope = app.scope.parent;
                    app.set(name, context);
                    return context;
                },

                _repeat: (expr, cb) => {
                    let data = app.parse(`{{${expr}}}`);
                    if (Array.isArray(data)) return data.forEach(cb);
                    return '';
                },

                _csrfToken: (overwrite) => {
                    return req.csrfToken(overwrite);
                },

                _csrfMeta: () => {
                    return `<meta name="csrf-token" content="${req.csrfToken()}">`;
                },

                _csrfInput: () => {
                    return `<input type="hidden" name="CSRFToken" value="${req.csrfToken()}">`;
                },

                _route: req.route.path
            };

            let template = page;
            if (layout && !req.fragment) {
                routeData.content = '/' + page;
                template = 'layouts/' + layout;
            }

            if (exec) {
                return Promise.resolve(app.define(exec, true)).then(() => {
                    if (!res.headersSent) {
                        app.set(app.parse(routeData));
                        debug(`Render template ${template}`);
                        debug(`Template data: %O`, Object.assign({}, app.global.data, app.data));
                        res.render(template, Object.assign({}, app.global.data, app.data, methods), async (err, html) => {
                            // callback is needed when using ejs with aync, html is a promise
                            if (err) return next(err);
                            html.then(html => res.send(html)).catch(err => next(err));
                        });
                    }
                }).catch(next)
            } else {
                app.set(app.parse(routeData));
                debug(`Render template ${template}`);
                debug(`Template data: %O`, app.global.data);
                res.render(template, Object.assign({}, app.global.data, methods), async (err, html) => {
                    // callback is needed when using ejs with aync, html is a promise
                    if (err) return next(err);
                    html.then(html => res.send(html)).catch(err => next(err));
                });
            }
        };
    }
};