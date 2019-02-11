/**
 * Authentication API error.
 */
export default class AuthError {
  /**
   * @param {string} title - Error title.
   * @param {string} detail - Error detail.
   */
  constructor (title, detail) {
    this.title = title
    this.detail = detail
    this.message = detail !== undefined ? detail : title
  }
}
