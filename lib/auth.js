'use strict'

/**
 * MailDev - auth.js
 * Cookie/token-based authentication middleware
 */

const crypto = require('crypto')

const validTokens = new Set()

function parseCookies (req) {
  const cookieHeader = req.headers.cookie || ''
  const cookies = {}
  cookieHeader.split(';').forEach(function (cookie) {
    const parts = cookie.trim().split('=')
    const name = parts.shift().trim()
    if (name) cookies[name] = decodeURIComponent(parts.join('=').trim())
  })
  return cookies
}

function createToken () {
  const token = crypto.randomBytes(32).toString('hex')
  validTokens.add(token)
  return token
}

function revokeToken (token) {
  validTokens.delete(token)
}

function isValidToken (token) {
  return Boolean(token && validTokens.has(token))
}

module.exports = function (basePathname, user, password) {
  const base = !basePathname || basePathname === '/' ? '' : basePathname

  return function (req, res, next) {
    // allow health checks without auth
    if (req.path === base + '/healthz') {
      return next()
    }

    const cookies = parseCookies(req)
    if (isValidToken(cookies.maildev_auth)) {
      return next()
    }

    // For API/JSON requests, return 401
    const accept = req.headers.accept || ''
    if (accept.includes('application/json') || req.headers['x-requested-with'] === 'XMLHttpRequest') {
      res.statusCode = 401
      return res.json({ error: 'Unauthorized' })
    }

    // Redirect to login page
    res.redirect(base + '/login')
  }
}

module.exports.createToken = createToken
module.exports.revokeToken = revokeToken
module.exports.isValidToken = isValidToken
module.exports.parseCookies = parseCookies
