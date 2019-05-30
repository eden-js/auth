// Require dependencies
const passport   = require('passport');
const Controller = require('controller');

// Require models
const Auth = model('auth');
const User = model('user');

/**
 * Export Auth Controller class
 *
 * @mount   /auth
 *
 * @extends controller
 */
class AuthController extends Controller {
  /**
   * Construct Auth Controller class
   */
  constructor() {
    // Run super
    super();

    // Set private variables
    this._types = [
      'discord',
    ];

    // Bind private methods
    this._authenticate = this._authenticate.bind(this);

    // Bind public methods
    this.authAction = this.authAction.bind(this);
    this.oneTimeAction = this.oneTimeAction.bind(this);
    this.authForceAction = this.authForceAction.bind(this);
    this.authRequestAction = this.authRequestAction.bind(this);
    this.authForceSubmitAction = this.authForceSubmitAction.bind(this);
  }

  /**
   * Authenticates a user
   *
   * @param  {string}   type
   * @param  {Request}  req
   * @param  {string}   identifier
   * @param  {string}   refreshToken
   * @param  {object}   profile
   * @param  {function} next
   *
   * @return {Promise}
   *
   * @private
   */
  async _authenticate(type, req, identifier, refreshToken, profile, next) {
    // Find an auth
    let auth = await Auth.findOne({
      id   : profile.id || identifier,
      type,
    });

    // Check req user
    if (req.user) {
      // Return user and auth
      return next(null, auth && await auth.get('user'), auth || new Auth({
        id      : profile.id || identifier,
        type,
        refresh : refreshToken,
        profile,
      }));
    }

    // Check auth
    if (auth) {
      // Set user
      const user = await auth.get('user');

      // Check user
      if (!user) {
        // Log error
        global.printError(auth.get('_id'));
      }

      // Check user registered
      if (user && !user.get('registered')) {
        // Lock auth
        await auth.lock();

        // Update auth
        auth.set('id', profile.id || identifier);
        auth.set('type', type);
        auth.set('refresh', refreshToken);
        auth.set('profile', profile);

        // Save auth
        await auth.save();

        // Unlock auth
        await auth.unlock();

        // Lock user
        await user.lock();

        // Set auths
        const auths = await user.get('auth') || [];

        // Push auth to auths
        auths.push(auth);

        // Update user
        user.set('auth', auths);
        user.set('registered', true);

        // Run user register hook
        await this.eden.hook('user.register', {
          req,
          auth,
          user,
        });

        // Save user
        await user.save();

        // Unlock user
        await user.unlock();
      }

      // Login user
      return next(null, user);
    }

    // Create new auth
    auth = new Auth({
      id      : profile.id || identifier,
      type,
      refresh : refreshToken,
      profile,
    });

    // Save auth
    await auth.save();

    // Set user
    const user = new User({
      registered : true,
    });

    // Set auths
    const auths = [auth];

    // Add auths to user
    user.set('auth', auths);

    // Run user register hook
    await this.eden.hook('user.register', {
      req,
      auth,
      user,
    });

    // Save user
    await user.save();

    // Set user in auth
    auth.set('user', user);

    // Save auth again
    await auth.save();

    // Login user
    return next(null, user);
  }

  /**
   * Auth action
   *
   * @acl   true
   * @fail  /login
   *
   * @route {get} /
   *
   * @param {Request}  req
   * @param {Response} res
   */
  authAction(req, res) {
    // Render auth
    res.render('auth');
  }

  /**
   * Auth request action
   *
   * @route  {get} /:type
   *
   * @param  {Request}  req
   * @param  {Response} res
   * @param  {function} next
   *
   * @return {Promise}
   *
   * @async
   */
  async authRequestAction(req, res, next) {
    // Clean type param
    req.params.type = req.params.type.toLowerCase();

    // Check type
    if (!this._types.includes(req.params.type)) {
      // Redirect to index
      res.redirect('/');
      return;
    }

    // Check user and type
    if (req.user && await Auth.count({
      type      : req.params.type,
      'user.id' : req.user.get('_id').toString(),
    })) {
      // Alert user
      req.alert('error', req.t('auth:register.exists', {
        type : req.params.type,
      }), {
        save : true,
      });

      // Redirect to auth
      res.redirect('/auth');
      return;
    }

    // Authenticate with passport
    passport.authenticate(req.params.type, async (error, user, auth) => {
      // Check req user
      if (req.user) {
        // Check user
        if (user && req.user.get('_id').toString() === user.get('_id').toString()) {
          // Alert user
          req.alert('error', req.t('auth:register.exists', {
            type : req.params.type,
          }), {
            save : true,
          });

          // Redirect to auth
          res.redirect('/auth');
          return;
        } if (user) {
          // Check force
          if (!req.session.force) {
            // Redirect to force auth
            res.redirect(`/auth/${req.params.type}/force`);
            return;
          }

          // Delete force
          delete req.session.force;

          // Lock user
          await user.lock();

          // Fetch auths from user
          const auths = await user.get('auth') || [];

          // Set index
          const index = auth.findIndex((element) => {
            // Return element check
            return element.get('_id').toString() === auth.get('_id').toString();
          });

          // Check index
          if (index > -1) {
            // Remove auth from auths
            auths.splice(index, 1);
          }

          // Update auths in user
          user.set('auth', auths);

          // Save user
          // await user.save();

          // Unlock user
          await user.unlock();
        }

        // Set user in auth
        auth.set('user', req.user);

        // Save auth
        await auth.save();

        // Lock req user
        await req.user.lock();

        // Fetch auths from req user
        const auths = await req.user.get('auth') || [];

        // Push auth to auths
        auths.push(auth);

        // Update auths in req user
        req.user.set('auth', auths);

        // Save req user
        await req.user.save();

        // Unlock req user
        await req.user.unlock();

        // Alert user
        req.alert('success', req.t('auth:register.success', {
          type : req.params.type,
        }), {
          save : true,
        });

        // Redirect to auth
        res.redirect('/auth');
        return;
      }

      // Check user
      if (!user) {
        // Alert user
        req.alert('error', error || req.t('auth:login.error', {
          type : req.params.type,
        }), {
          save : true,
        });

        // Redirect to login
        res.redirect('/login');
        return;
      }

      // Log user in
      req.login(user, {}, async (loginError) => {
        // Check error
        if (loginError) {
          // Alert user
          req.alert('error', loginError, {
            save : true,
          });

          // Redirect to login
          res.redirect('/login');
          return;
        }

        // Run user login hook
        await this.eden.hook('user.login', user);

        // Alert user
        req.alert('success', req.t('auth:login.success', {
          type : req.params.type,
        }), {
          save : true,
        });

        // Redirect to home
        res.redirect('/');
      });
    })(req, res, next);
  }

  /**
   * Auth force action
   *
   * @acl   true
   * @fail  /login
   *
   * @route {get} /:type/force
   *
   * @param {Request}  req
   * @param {Response} res
   */
  authForceAction(req, res) {
    // Render force
    res.render('auth/force', {
      type : req.params.type,
    });
  }

  /**
   * Auth force submit action
   *
   * @acl   true
   * @fail  /login
   *
   * @route {post} /:type/force
   *
   * @param {Request}  req
   * @param {Response} res
   */
  authForceSubmitAction(req, res) {
    // Render force
    res.render('auth/force', {
      type : req.params.type,
    });
  }

  /**
   * One time auth action
   *
   * @param  {Request}  req
   * @param  {Response} res
   * @param  {Function} next
   *
   * @route  {GET} /:otp/:redirect
   * @return {Promise}
   */
  async oneTimeAction(req, res, next) {
    // One time
    const otpUser = await User.findOne({
      otp : req.params.otp,
    });

    // If no otp
    if (!otpUser) {
      next();
      return;
    }

    // Login user
    await new Promise((resolve) => {
      // Login user
      req.login(otpUser, () => {
        // Resolve
        resolve();
      });
    });

    // Remove otp
    await otpUser.lock();

    // Unset otp
    otpUser.unset('otp');

    // Save otp user
    await otpUser.save();

    // Unlock user
    otpUser.unlock();

    // Redirect
    res.redirect(req.params.redirect);
  }
}

/**
 * Export Auth Controller class
 *
 * @type {AuthController}
 */
module.exports = AuthController;
