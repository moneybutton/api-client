/**
 * REST API error.
 */
export default class RestError {
  /**
   *
   * @param {number} status - HTTP status code.
   * @param {string} title - Error title.
   * @param {string} detail - Error detail.
   */
  constructor (status, title, detail) {
    this.status = status
    this.title = title
    this.detail = detail
    this.message = detail !== undefined ? detail : title
  }
}
