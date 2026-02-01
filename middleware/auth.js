/**
 * Middleware to check if user is authenticated
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.redirect('/?error=Please login first');
}

/**
 * Middleware to check if user is already logged in
 * (redirect to dashboard if so)
 */
function redirectIfAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return res.redirect('/dashboard');
  }
  next();
}

module.exports = {
  requireAuth,
  redirectIfAuthenticated
};
