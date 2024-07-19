const fp = require('fastify-plugin');
const err = require('http-errors');
const { promisify } = require('util');
const crypto = require('crypto');
const scryptAsync = promisify(crypto.scrypt);
const { encrypt, decrypt } = require('./utils');

const default_opts = {
    /**
     * Custom validation function that is called after basic validation is executed
     * This function should throw in case validation fails
     * @param { import('fastify').FastifyRequest } request fastify request object
     * @param { import('fastify').FastifyReply } reply  fastify reply object
     */
    extra_validation: /* istanbul ignore next */ async function validation (request, reply){
        //by default does nothing
    },

    /** Secure key that will be used to do the encryption stuff */
    secret: '',
    
    /** Request header name / query parameter name / cookie name */
    header_name: 'authorization',

    /** Set this to true if you don't want to allow the token to be passed as a header */
    disable_headers: false,

    /** Set this to true if you don't want to allow the token to be passed as a query parameter */
    disable_query: false,

    /** Set this to true if you don't want to allow the token to be passed as a cookie */
    disable_cookies: false,

    /** Sets the token prefix, by default `'Bearer '` is used. A null value means no prefix */
    token_prefix: 'Bearer ',

    /**
     * Allows for renaming the decorators this plugin adds to Fastify.
     * Useful if you want to register this plugin multiple times in the same scope
     * (not usually needed, but can be useful sometimes).
     * 
     * Note: if using TypeScript and intending to use this feature, you'll probably
     * want to add type definitions for the renamed decorators, otherwise it might complain
     * that they don't exist.
     * */
    rename_decorators: {
        /** Change the name of the `FastifyInstance.requireAuthentication` decorator */
        requireAuthentication: 'requireAuthentication',

        /** Change the name of the `FastifyInstance.generateAuthToken` decorator */
        generateAuthToken: 'generateAuthToken',
        
        /** Change the name of the `FastifyRequest.auth` decorator */
        auth: 'auth',
    }
};

function validateOptions(opts) {
    if (opts.rename_decorators) {
        opts.rename_decorators = Object.assign({}, default_opts.rename_decorators, opts.rename_decorators);
    }
    opts = Object.assign({}, default_opts, opts);

    if (!opts.header_name) throw new Error('header_name cannot be null');
    if (typeof opts.header_name !== 'string') throw new Error('header_name should be a string');
    if (!opts.secret || opts.secret.length < 20) throw new Error('the secret cannot be null and should have at least 20 characters to be considered secure');
    if (opts.extra_validation != null && typeof opts.extra_validation !== 'function') throw new Error('extra validation should be either null or a function');
    if (opts.disable_headers && opts.disable_query && opts.disable_cookies) throw new Error('at least one of the following flags should be false: disable_headers, disable_query, disable_cookies');
    if (opts.token_prefix != null && typeof opts.token_prefix !== 'string') throw new Error('token_prefix should be either null or a string');
    if (!opts.rename_decorators.auth || typeof opts.rename_decorators.auth !== 'string') throw new Error('rename_decorators.auth should be a non empty string');
    if (!opts.rename_decorators.generateAuthToken || typeof opts.rename_decorators.generateAuthToken !== 'string') throw new Error('rename_decorators.generateAuthToken should be a non empty string');
    if (!opts.rename_decorators.requireAuthentication || typeof opts.rename_decorators.requireAuthentication !== 'string') throw new Error('rename_decorators.requireAuthentication should be a non empty string');
    if (opts.rename_decorators.generateAuthToken === opts.rename_decorators.requireAuthentication) throw new Error('rename_decorators.generateAuthToken and rename_decorators.requireAuthentication should have distinct values');
}

async function plugin(fastify, options) {
    const opts = Object.assign({}, default_opts, options);
    validateOptions(opts);

    const key = await scryptAsync(opts.secret, opts.header_name, 32);

    async function validation(req, reply) {
        let field = null;
        if (!opts.disable_headers && req.headers[opts.header_name]) field = req.headers[opts.header_name];
        else if (!opts.disable_query && req.query[opts.header_name]) field = req.query[opts.header_name];
        else if (!opts.disable_cookies && req.cookies && req.cookies[opts.header_name]) field = req.cookies[opts.header_name];

        if (!field) throw new err.Unauthorized();

        let token;
        if (opts.token_prefix != null) {
            if (field.substring(0, opts.token_prefix.length) !== opts.token_prefix) throw new err.Forbidden();
            token = field.substring(opts.token_prefix.length, field.length);
        } else {
            token = field;
        }

        try {
            const json = await decrypt(key, token);
            req[opts.rename_decorators.auth] = json === '`' ? {} : JSON.parse(json);
        } catch (ex) {
            throw new err.Forbidden();
        }

        if (opts.extra_validation != null) await opts.extra_validation(req, reply);
    }

    function requireAuthentication(fastify) {
        fastify.addHook('preHandler', validation);
    }

    async function generateAuthToken(data) {
        const prefix = opts.token_prefix != null ? opts.token_prefix : '';
        if (!data || Object.keys(data).length < 1) return prefix + await encrypt(key, '`');
        return prefix + await encrypt(key, JSON.stringify(data));
    }

    fastify.decorate(opts.rename_decorators.requireAuthentication, requireAuthentication);
    fastify.decorate(opts.rename_decorators.generateAuthToken, generateAuthToken);
}

module.exports = fp(plugin);