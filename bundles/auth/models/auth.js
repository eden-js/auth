// Require local class dependencies
const Model = require('model');

/**
 * Create Auth Model class
 */
class Auth extends Model {
  /**
   * Initialize Auth Model class
   */
  static async initialize() {
    // Create id index
    await this.createIndex('id', {
      id : -1,
    });

    // Create type index
    await this.createIndex('type', {
      type : -1,
    });

    // Create id+type index
    await this.createIndex('id+type', {
      id   : -1,
      type : -1,
    });

    // Create user index
    await this.createIndex('userID', {
      'user.id' : -1,
    });
  }

  /**
   * Sanitise auth
   *
   * @returns {Promise<Object>}
   */
  async sanitise(...args) {
    // Check args
    if (args && args.length) {
      // Return sanitised with args
      return await super.__sanitiseModel(...args);
    }

    // Return sanitised auth
    return await super.__sanitiseModel({
      field          : '_id',
      default        : null,
      sanitisedField : 'id',
      sanitise       : (id) => {
        // Return sanitised id
        return id ? id.toString() : null;
      },
    });
  }
}

/**
 * Export Auth Model class
 *
 * @type {Auth}
 */
module.exports = Auth;
