import {
  toResourceObject,
  toNewResourceObject,
  fromResourceObject,
  fromResourceObjectsOfType,
  toJsonApiData,
  toJsonApiDataIncluding,
  fromJsonApiData,
  fromJsonApiDataIncluding,
  jsonSerializers,
  JsonDeserializer
} from '@moneybutton/json-api'
import fetch from 'isomorphic-fetch'
import moment from 'moment'
import queryString from 'query-string'
import uuid from 'uuid'

import AuthError from './auth-error'
import config from './config'
import RestError from './rest-error'
import sha256 from 'fast-sha256'

const API_REST_URI = config.get('MONEY_BUTTON_API_REST_URI')
const API_AUTH_URI = config.get('MONEY_BUTTON_API_AUTH_URI')

const LOGIN_PASSWORD_HMAC_KEY = 'yours login password'

const STORAGE_NAMESPACE = 'mb_js_client'
const OAUTH_REDIRECT_URI_KEY = [STORAGE_NAMESPACE, 'oauth_redirect_uri'].join(':')
const OAUTH_STATE_KEY = [STORAGE_NAMESPACE, 'oauth_state'].join(':')
const OAUTH_ACCESS_TOKEN_KEY = [STORAGE_NAMESPACE, 'oauth_access_token'].join(':')
const OAUTH_EXPIRATION_TIME_KEY = [STORAGE_NAMESPACE, 'oauth_expiration_time'].join(':')
const OAUTH_REFRESH_TOKEN_KEY = [STORAGE_NAMESPACE, 'oauth_refresh_token'].join(':')
const CURRENT_USER_CACHE_KEY = [STORAGE_NAMESPACE, 'current_user'].join(':')
const APP_REFRESH_STRATEGY = 'client_credentials'
const DEFAULT_REFRESH_STRATEGY = 'refresh_token'

const {
  UserSerializer,
  PaymentSerializer,
  EmailVerificationSerializer
} = jsonSerializers

/**
 * @param {Storage} webStorage - Object conforming to the Storage Web API.
 * @param {Crypto} webCrypto - Object conforming to the Crypto Web API.
 * @param {Location} webLocation - Object conforming to the Location Web API.
 */
export default function getMoneyButtonClient (webStorage, webCrypto, webLocation) {
  if (!webStorage) {
    throw new Error('Missing required web storage object.')
  }
  if (!webCrypto || !webCrypto.subtle) {
    throw new Error('Missing required web crypto object.')
  }
  if (!webLocation) {
    throw new Error('Missing required web location object.')
  }
  /**
   *
   */
  class MoneyButtonClient {
    /**
     * Creates an instance of Money Button for the given OAuth client.
     *
     * @param {string} clientId - OAuth client's identifier.
     * @param {string} clientSecret - OAuth client's secret.
     */
    constructor (clientId, clientSecret = null) {
      this.clientId = clientId
      this.clientSecret = clientSecret
      this.refreshStrategy = DEFAULT_REFRESH_STRATEGY
    }

    /**
     * Logs in the user with the given email and password.
     *
     * @param {string} email
     * @param {string} password
     * @returns {undefined}
     */
    async logIn (email, password) {
      const loginPassword = await MoneyButtonClient._computeHmac256(
        LOGIN_PASSWORD_HMAC_KEY,
        password
      )
      this._clearCurrentUser()
      await this._logIn(email, loginPassword)
    }

    /**
     * Get tokens to log in as an app.
     * It changes the internal state of the client.
     */
    async logInAsApp () {
      await this._doClientCredentialsGrantAccessTokenRequest('application_access:write')
      this._clearCurrentUser()
      this.refreshStrategy = APP_REFRESH_STRATEGY
    }

    /**
     * Logs in the user with the given email and login password.
     *
     * @private
     * @param {string} email
     * @param {string} password
     * @returns {undefined}
     */
    async _logIn (email, loginPassword) {
      if (await this.isLoggedIn()) {
        this.logOut()
      }
      await this._doResourceOwnerPasswordCredentialsGrantAccessTokenRequest(
        email,
        loginPassword,
        'general_access:write'
      )
    }

    /**
     * Determines whether a user is currently logged-in.
     *
     * @returns {boolean}
     */
    async isLoggedIn () {
      const accessToken = await this.getValidAccessToken()
      return accessToken !== null
    }

    /**
     * Retrieves a valid access token for the currently logged-in user.
     * Returns null if no user is currently logged-in.
     *
     * @returns {string|null}
     */
    async getValidAccessToken () {
      let accessToken = this.getAccessToken()
      if (
        accessToken !== null &&
        moment().isBefore(moment(this.getExpirationTime()))
      ) {
        return accessToken
      }
      if (this.refreshStrategy === APP_REFRESH_STRATEGY) {
        await this.logInAsApp()
        return this.getAccessToken()
      } else {
        const refreshToken = this.getRefreshToken()
        if (refreshToken === null) {
          return null
        }
        accessToken = null
        try {
          await this._doRefreshAccessTokenRequest(refreshToken)
          accessToken = this.getAccessToken()
        } catch (err) {
          if (!(err instanceof AuthError)) {
            throw err
          }
        }
        return accessToken
      }
    }

    /**
     * Logs out the current logged-in user, if any.
     */
    logOut () {
      Array.from(Array(webStorage.length).keys()) // Generates a range of integers from 0 to webStorage.length
        .map(i => webStorage.key(i))
        .filter(key => key.startsWith('mb_wallet') || key.startsWith(STORAGE_NAMESPACE))
        .forEach(key => webStorage.removeItem(key))
    }

    /**
     * Finishes the email verification process with the access token generated
     * during signup.
     *
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */
    async verifyEmail (accessToken) {
      const json = await this._doPostRequest(
        '/v1/auth/email_verification',
        {},
        {},
        accessToken
      )
      this._clearCurrentUser()
      return fromResourceObject(fromJsonApiData(json), 'email_verifications')
    }

    /**
     * Re send message to validate email address.
     * @param {string} email
     */
    async resendEmailAddressVerification (email) {
      const body = EmailVerificationSerializer.serialize({ email })
      await this._doPostRequest('/v1/auth/resend_verification_email', body)
      this._clearCurrentUser()
    }

    /**
     * Retrieves the currently logged user's identity.
     *
     * @returns {object}
     */
    async getIdentity () {
      const json = await this._doGetRequest('/v1/auth/user_identity')
      return fromResourceObject(fromJsonApiData(json), 'user_identities')
    }

    /**
     * Returns an object with two keys:
     * - loggedIn: a boolean indicating whether there is a currently logged-in user.
     * - user: if loggedIn is true, this is an object with the user's attributes.
     *
     * @returns {object}
     */
    async whoAmI () {
      const loggedIn = await this.isLoggedIn()
      if (!loggedIn) {
        return { loggedIn }
      }

      const currentUser = this._getCurrentUser()
      if (currentUser) {
        return { loggedIn: true, user: currentUser }
      }

      const { id } = await this.getIdentity()
      const user = await this.getUser(id)
      this._setCurrentUser(user)
      return { loggedIn, user }
    }

    /**
     * Changes the currently logged-in user's password.
     *
     * @param {string} password
     * @param {string} encryptedMnemonic
     * @param {string} xpub
     * @param {string} language
     * @returns {object}
     */
    async changePassword (
      password,
      encryptedMnemonic,
      xpub,
      language
    ) {
      const loginPassword = await MoneyButtonClient._computeHmac256(
        LOGIN_PASSWORD_HMAC_KEY,
        password
      )
      const body = toJsonApiDataIncluding(
        toNewResourceObject('users', {
          password: loginPassword
        }),
        [
          toNewResourceObject('wallets', {
            encryptedMnemonic,
            xpub,
            language
          })
        ]
      )
      const json = await this._doPostRequest('/v1/auth/password_change', body)
      return fromResourceObject(fromJsonApiData(json), 'password_changes')
    }

    /**
     * Resets the currently logged-in user's password by using the access token
     * generated during the "I forgot my password" flow.
     *
     * @param {string} accessToken - auth API access token
     * @param {string} password
     * @param {string} encryptedMnemonic
     * @param {string} xpub
     * @param {boolean} forceCreate
     * @param {string} walletLanguage
     * @returns {object}
     */
    async resetPassword (
      accessToken,
      password,
      encryptedMnemonic,
      xpub,
      forceCreate,
      walletLanguage
    ) {
      const loginPassword = await MoneyButtonClient._computeHmac256(
        LOGIN_PASSWORD_HMAC_KEY,
        password
      )
      const body = toJsonApiDataIncluding(
        toNewResourceObject('users', {
          password: loginPassword
        }),
        [
          toNewResourceObject('wallets', {
            encryptedMnemonic,
            xpub,
            language: walletLanguage
          })
        ]
      )
      const query = forceCreate ? { forceCreate: 'true' } : {}
      const json = await this._doPostRequest(
        '/v1/auth/password_reset',
        body,
        query,
        accessToken
      )
      this._clearCurrentUser()
      return fromResourceObject(fromJsonApiData(json), 'password_resets')
    }

    /**
     * Sends a password reset email to begin the "I forgot my password" flow.
     *
     * @param {string} email
     * @returns {object}
     */
    async sendPasswordReset (email) {
      if (await this.isLoggedIn()) {
        this.logOut()
      }
      await this._doClientCredentialsGrantAccessTokenRequest(
        'auth.password_reset_email:write'
      )
      const attributes = { email }
      const body = toJsonApiData(toNewResourceObject('users', attributes))
      const json = await this._doPostRequest('/v1/auth/password_reset_email', body)
      this.logOut()
      return fromResourceObject(fromJsonApiData(json), 'password_reset_emails')
    }

    /**
     * Creates a new user account with the given email and password.
     *
     * @param {string} email
     * @param {string} password
     * @returns {object}
     */
    async signUp (email, password) {
      const loginPassword = await MoneyButtonClient._computeHmac256(
        LOGIN_PASSWORD_HMAC_KEY,
        password
      )
      return this._signUp(email, loginPassword)
    }

    /**
     * Creates a new user account with the given email and login password.
     *
     * @private
     * @param {string} email
     * @param {string} loginPassword
     * @returns {object}
     */
    async _signUp (email, loginPassword) {
      if (await this.isLoggedIn()) {
        this.logOut()
      }
      await this._doClientCredentialsGrantAccessTokenRequest(
        'auth.signup:write'
      )
      const attributes = {
        email,
        password: loginPassword
      }
      const body = toJsonApiData(toNewResourceObject('users', attributes))
      const json = await this._doPostRequest('/v1/auth/signup', body)
      await this._logIn(email, loginPassword)
      return fromResourceObject(fromJsonApiData(json), 'signups')
    }

    /**
     * [Browser only] Starts the authorization flow which allows third-party applications
     * to request access to user resources on their behalf. This function will
     * redirect the user's window to the Money Button's authorization flow page.
     *
     * @param {string} scope - scope to be requested to the user.
     * @param {string} redirectUri - URI where the authorization response will be handled.
     * @returns {undefined}
     */
    requestAuthorization (
      scope,
      redirectUri,
      state = null
    ) {
      if (typeof scope !== 'string' || scope.length === 0) {
        throw new Error(`Invalid scope requested: ${scope}.`)
      }
      if (typeof redirectUri !== 'string' || redirectUri.length === 0) {
        throw new Error(`Invalid return URI: ${redirectUri}.`)
      }
      this._doAuthorizationCodeGrantAuthorizationRequest(redirectUri, scope, state)
    }

    /**
     * [Browser only] Finishes the authorization flow started by {@link requestAuthorization}.
     * If successful, after calling this function, the client will be able to perform requests
     * on behalf of the user as long as they are within the scope requested when starting the
     * authorization flow.
     *
     * @returns {undefined}
     */
    async handleAuthorizationResponse () {
      const { error, code, state } = this._getUrlQuery()
      const redirectUri = this._getRedirectUri()
      if (!redirectUri) {
        throw new Error('Required OAuth redirect URI not found in storage.')
      }
      await this._handleAuthorizationCodeGrantAuthorizationResponse(error, code, state, this._getState(), this._getRedirectUri())
    }

    async authorizeWithAuthFlowResponse (queryParams, expectedState, redirectUri) {
      const { error, code, state } = queryParams
      await this._handleAuthorizationCodeGrantAuthorizationResponse(error, code, state, expectedState, redirectUri)
    }

    /**
     * See: https://tools.ietf.org/html/rfc6749#page-24.
     *
     * @private
     * @param {string} redirectUri
     * @param {string} scope
     */
    _doAuthorizationCodeGrantAuthorizationRequest (
      redirectUri,
      scope,
      state = null
    ) {
      if (this.clientSecret !== null) {
        throw new Error([
          'Grant `authentication_code` can only be performed by ',
          'a public client (that is, a client with no client secret).'
        ].join(''))
      }
      if (state === null) {
        state = uuid.v4()
      }
      this._setRedirectUri(redirectUri)
      this._setState(state)
      const authorizationUri = [
        `${API_AUTH_URI}/oauth/v1/authorize`,
        queryString.stringify({
          response_type: 'code',
          client_id: this.clientId,
          redirect_uri: redirectUri,
          scope,
          state
        })
      ].join('?')
      this._redirectToUri(authorizationUri)
    }

    /**
     * See: https://tools.ietf.org/html/rfc6749#page-26.
     *
     * @private
     */
    async _handleAuthorizationCodeGrantAuthorizationResponse (
      error,
      code,
      state,
      expectedState,
      redirectUri
    ) {
      if (error !== undefined) {
        throw new AuthError('Authorization failed.', error)
      }
      if (code === undefined) {
        throw new Error('Missing OAuth authorization code.')
      }
      if (expectedState === null || state !== expectedState) {
        throw new Error('Invalid OAuth state.')
      }
      await this._doAuthorizationCodeGrantAccessTokenRequest(code, redirectUri)
    }

    /**
     * See: https://tools.ietf.org/html/rfc6749#page-29.
     *
     * @private
     */
    async _doAuthorizationCodeGrantAccessTokenRequest (
      code,
      redirectUri
    ) {
      if (!redirectUri) {
        throw new Error('Required OAuth redirect URI not found.')
      }
      await this._doAccessTokenRequest(
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: this.clientId
        }
      )
    }

    /**
     * See: https://tools.ietf.org/html/rfc6749#page-37.
     *
     * @private
     */
    async _doResourceOwnerPasswordCredentialsGrantAccessTokenRequest (
      username,
      password,
      scope
    ) {
      await this._doAccessTokenRequest(
        {
          grant_type: 'password',
          username,
          password,
          scope
        },
        this._buildBasicAuthHeaders()
      )
    }

    /**
     * See: https://tools.ietf.org/html/rfc6749#page-41.
     *
     * @private
     */
    async _doClientCredentialsGrantAccessTokenRequest (scope) {
      await this._doAccessTokenRequest(
        {
          grant_type: 'client_credentials',
          scope
        },
        this._buildBasicAuthHeaders()
      )
    }

    /**
     * @private
     * @param {string} refreshToken
     */
    async _doRefreshAccessTokenRequest (refreshToken) {
      await this._doAccessTokenRequest(
        {
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: this.clientId
        },
        this._buildBasicAuthHeaders()
      )
    }

    /**
     * @private
     */
    _buildBasicAuthHeaders () {
      if (this.clientSecret === null) {
        return {}
      }
      const credentials = `${this.clientId}:${this.clientSecret}`
      return {
        Authorization: `Basic ${Buffer.from(credentials).toString('base64')}`
      }
    }

    /**
     * @private
     * @param {object} body
     * @param {object} headers
     */
    async _doAccessTokenRequest (body = {}, headers = {}) {
      const res = await fetch(
        `${API_AUTH_URI}/oauth/v1/token`,
        {
          method: 'POST',
          body: queryString.stringify(body),
          headers: {
            ...headers,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      )
      await this._handleAccessTokenResponse(res)
    }

    /**
     * @private
     * @param {Response} res - Express.js response object.
     */
    async _handleAccessTokenResponse (res) {
      const {
        error,
        error_description: errorDescription,
        errors,
        access_token: accessToken,
        token_type: tokenType,
        expires_in: expiresIn,
        refresh_token: refreshToken
      } = await res.json()

      if (error !== undefined && error !== null) {
        throw new AuthError(error, errorDescription)
      }
      if (errors) {
        console.error(errors)
        throw new AuthError(errors[0], errors[0])
      }
      if (tokenType !== 'Bearer') {
        throw new Error('Unexpected token type.')
      }
      if (accessToken !== undefined && accessToken !== null) {
        this.setAccessToken(accessToken)
      } else {
        this.clearAccessToken()
      }
      if (expiresIn !== undefined && expiresIn !== null) {
        const expirationTime = moment().add(expiresIn, 'seconds')
        this.setExpirationTime(expirationTime.format())
      } else {
        this.clearExpirationTime()
      }
      if (refreshToken !== undefined && refreshToken !== null) {
        this.setRefreshToken(refreshToken)
      } else {
        this.clearRefreshToken()
      }
    }

    /**
     * Get basic information from the OAuth client with the given identifier.
     *
     * @param {string} clientIdentifier
     * @returns {object}
     */
    async getClientByIdentifier (clientIdentifier) {
      const json = await this._doGetRequest(`/v1/clients/client_identifier=${clientIdentifier}`)
      return fromResourceObject(fromJsonApiData(json), 'clients')
    }

    /**
     * Get basic information from the OAuth app with the given identifier.
     *
     * @param {string} oAuthIdentifier
     * @returns {object}
     */
    async getAppProfileByOAuthIdentifier (oAuthIdentifier) {
      const json = await this._doGetRequest(`/v1/application_profiles/oauth_identifier=${oAuthIdentifier}`)
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Retrives the user with the given handle.
     *
     * @param {string} handle
     * @returns {object}
     */
    async getUserByHandle (handle) {
      let json = await this._doGetRequest(`/v1/users/handle/${handle}`)
      return fromResourceObject(fromJsonApiData(json), 'users')
    }

    /**
     * Retrives the user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */
    async getUser (userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}`)
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Retrives the profile of user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */
    async getUserProfile (userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/profile`)
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Updates the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async updateUser (userId, attributes = {}) {
      const body = UserSerializer.serialize(attributes)
      const json = await this._doPatchRequest(`/v1/users/${userId}`, body)
      this._clearCurrentUser()
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Retrives the transaction history of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */
    async getUserTransactionHistory (userId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/transaction_history`,
        query
      )
      return fromResourceObjectsOfType(
        fromJsonApiData(json),
        'transaction_history'
      )
    }

    /**
     * Retrives the OAuth clients of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */
    async getUserClients (userId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/clients`,
        query
      )
      return fromResourceObjectsOfType(fromJsonApiData(json), 'clients')
    }

    /**
     * Retrives paginated utxos for the specified user
     *
     * @param {string} userId
     * @returns {list}
     */
    async getUserUtxos (userId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/utxos`,
        query
      )
      return fromResourceObjectsOfType(fromJsonApiData(json), 'utxos')
    }

    /**
     * Retrives an specific utxo for a user
     *
     * @param {string} userId
     * @param {string} utxoId
     * @returns {list}
     */
    async getUserUtxoById (userId, utxoId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/utxos/${utxoId}`,
        query
      )
      return fromResourceObject(fromJsonApiData(json), 'utxos')
    }

    /**
     * Retrives all the applications belonging to the specified user.
     *
     * @param {string} userId
     * @returns {list}
     */
    async getUserApplications (userId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/applications`,
        query
      )
      return fromResourceObjectsOfType(fromJsonApiData(json), 'applications')
    }

    async getUserApplicationById (userId, appId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/applications/${appId}`,
        query
      )
      return fromResourceObject(fromJsonApiData(json), 'applications')
    }

    async createUserApplication (userId, attributes) {
      const body = toJsonApiData(toNewResourceObject('applications', attributes))
      const json = await this._doPostRequest(
        `/v1/users/${userId}/applications`,
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'applications')
    }

    async updateUserApplication (userId, appId, attributes) {
      const body = toJsonApiData(toResourceObject(appId, 'applications', attributes))
      const json = await this._doPatchRequest(
        `/v1/users/${userId}/applications/${appId}`,
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'applications')
    }

    /**
     * Creates an OAuth client for the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async createUserClient (userId, attributes) {
      let body = toJsonApiData(toNewResourceObject('clients', attributes))
      const json = await this._doPostRequest(`/v1/users/${userId}/clients`, body)
      return fromResourceObject(fromJsonApiData(json), 'clients')
    }

    /**
     * Updates an OAuth client for the user with the given user id.
     *
     * @param {string} userId
     * @param {string} clientId
     * @param {object} attributes
     * @returns {object}
     */
    async updateUserClient (userId, clientId, attributes = {}) {
      const body = toJsonApiData(
        toResourceObject(clientId, 'clients', attributes)
      )
      await this._doPatchRequest(
        `/v1/users/${userId}/clients/${clientId}`,
        body
      )
    }

    /**
     * Retrives the handles of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */
    async getUserHandles (userId, query = {}) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/handles`,
        query
      )
      return fromResourceObjectsOfType(fromJsonApiData(json), 'handles')
    }

    /**
     * Update a handle with the proper data
     *
     * @param {string} handleId
     * @param {object} attributes
     * @returns {object}
     */
    async updateUserHandle (userId, handleId, attributes = {}) {
      const body = toJsonApiData(toResourceObject(handleId, 'handles', attributes))
      const json = await this._doPatchRequest(
        `/v1/users/${userId}/handles/${handleId}`,
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'handles')
    }

    /**
     * Retrives the handles of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */
    async checkHandleAvailability (search, query = {}) {
      let body = toJsonApiData(toNewResourceObject('handleChecks', { search }))
      const json = await this._doPostRequest(
        `/v1/handles/check`,
        body,
        query
      )
      return fromResourceObject(fromJsonApiData(json), 'handleAvailabilities')
    }

    /**
     * Creates a handle for the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async createUserHandle (userId, attributes) {
      let body = toJsonApiData(toNewResourceObject('handles', attributes))
      const json = await this._doPostRequest(`/v1/users/${userId}/handles`, body)
      return fromResourceObject(fromJsonApiData(json), 'handles')
    }

    /**
     * Retrives the wallet with the given wallet id for the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */
    async getUserWallet (userId, walletId) {
      let json = await this._doGetRequest(
        `/v1/users/${userId}/wallets/${walletId}`
      )
      return fromResourceObject(fromJsonApiData(json), 'wallets')
    }

    /**
     * Retrives the wallets of the user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */
    async getUserWallets (userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/wallets/`)
      return fromResourceObjectsOfType(fromJsonApiData(json), 'wallets')
    }

    /**
     * Retrives the max withdrawal amount for the wallet with the given wallet id,
     * belonging to the user with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */
    async getMaxWithdrawalForWallet (userId, walletId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/wallets/${walletId}/max_withdrawal`)
      return fromResourceObject(fromJsonApiData(json), 'amounts')
    }

    /**
     * Creates a wallet for the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async createUserWallet (userId, attributes) {
      let body = toJsonApiData(toNewResourceObject('wallets', attributes))
      let json = await this._doPostRequest(`/v1/users/${userId}/wallets`, body)
      this._clearCurrentUser()
      return fromResourceObject(fromJsonApiData(json), 'wallets')
    }

    /**
     * Retrieves the balance from the user with given user id.
     *
     * @param {string} userId
     * @returns {object}
     */
    async getBalance (userId) {
      const json = await this._doGetRequest(`/v1/users/${userId}/balance`)
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Retrives the max withdrawal amount the user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */
    async getMaxWithdrawal (userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/max_withdrawal`)
      return fromResourceObject(fromJsonApiData(json), 'amounts')
    }

    /**
     * Retrives a recieve address for the user with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */
    async getReceiveAddress (userId, walletId) {
      let json = await this._doPostRequest(
        `/v1/users/${userId}/wallets/${walletId}/receive_address`
      )
      let { address } = fromResourceObject(fromJsonApiData(json), 'addresses')
      return address
    }

    /**
     * Converts a (curreny,amount) pair into the given user's default currency.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async getCurrencyAmount (userId, attributes) {
      const body = toJsonApiData(toNewResourceObject('currency', attributes))
      const json = await this._doPostRequest(
        `/v1/users/${userId}/currency`,
        body
      )
      const { amount, currency } = fromResourceObject(
        fromJsonApiData(json),
        'currency'
      )
      return { amount, currency }
    }

    /**
     * Retrives the balance for the wallet with the given wallet id,
     * belonging to the user with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */
    async getWalletBalance (userId, walletId) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/wallets/${walletId}/balance`
      )
      return fromResourceObject(fromJsonApiData(json), 'amounts')
    }

    /**
     * Updates the wallet with the given wallet id, belonging to the user
     * with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @param {object} attributes
     * @returns {object}
     */
    async updateWallet (userId, walletId, attributes) {
      const body = toJsonApiData(
        toResourceObject(walletId, 'wallets', attributes)
      )
      await this._doPatchRequest(
        `/v1/users/${userId}/wallets/${walletId}`,
        body
      )
    }

    /**
     * Retrieves the payments from the user with the given user id.
     *
     * @param {string} userId
     * @param {object} paginate
     * @returns {object}
     */
    async getUserPayments (userId, paginate) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/payments?${this._paginateUri(paginate)}`
      )
      return {
        pages: json.meta['total-pages'],
        payments: json.data.map(payment =>
          fromResourceObject(payment, 'payments')
        )
      }
    }

    /**
     * Query for a list of payments belonging to the user or app logged in in the client.
     *
     * @param {object} query Query parameters
     * @param {object} query.limit Pagination. Max amount of record returned.
     * @param {object} query.offset Pagination offset.
     */
    async getOwnPayments (query) {
      const json = await this._doGetRequest(
        `/v1/payments`,
        query
      )
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Query a payment by id.
     *
     * @param {number} paymentId
     */
    async getPaymentById (paymentId) {
      const json = await this._doGetRequest(
        `/v1/payments/${paymentId}`
      )
      return JsonDeserializer.deserialize(json)
    }

    /**
     * @private
     * @returns {string}
     */
    _paginateUri ({ number, size, sort }) {
      // NOTE: query-string does not support the nesting format used in JsonApi
      // https://github.com/sindresorhus/query-string#nesting
      // http://jsonapi.org/examples/#pagination
      // http://jsonapi.org/format/#fetching-pagination
      const url = []
      if (number) url.push(`page[number]=${number}`)
      if (size) url.push(`page[size]=${size}`)
      if (sort) url.push(`sort=${sort}`)
      return url.join('&')
    }

    /**
     * Creates a payment for the user with the given user id to the specified payment
     * outputs.
     *
     * @param {string} userId
     * @param {object} attributes
     * @param {array} paymentOutputs
     * @returns {object}
     */
    async createUserPayment (userId, attributes, paymentOutputs, cryptoOperations = []) {
      let body = PaymentSerializer.serialize({
        ...attributes,
        paymentOutputs,
        cryptoOperations
      })
      let json = await this._doPostRequest(`/v1/users/${userId}/payments`, body)
      let { data, included } = fromJsonApiDataIncluding(json)
      let payment = fromResourceObject(data, 'payments')
      let [bsvTransaction] = fromResourceObjectsOfType(included, 'bsv_transactions')
      let addressIndexes = fromResourceObjectsOfType(
        included,
        'address_indexes'
      )
        .sort((a, b) => a.index - b.index)
        .map(addressIndex => addressIndex.addressIndex)
      return {
        payment,
        paymentOutputs: fromResourceObjectsOfType(included, 'payment_outputs'),
        bsvTransaction,
        addressIndexes
      }
    }

    /**
     * Creates a simulated payment used for displaying accurate fee information.
     *
     * @param {string} userId
     * @param {object} attributes
     * @param {array} paymentOutputs
     * @returns {object}
     */
    async createSimulatedUserPayment (userId, attributes, paymentOutputs, cryptoOperations = []) {
      let body = PaymentSerializer.serialize({
        ...attributes,
        paymentOutputs,
        cryptoOperations
      })
      let json = await this._doPostRequest(`/v1/users/${userId}/payments/simulated`, body)
      let { data, included } = fromJsonApiDataIncluding(json)
      let payment = fromResourceObject(data, 'payments')
      let [bsvTransaction] = fromResourceObjectsOfType(included, 'bsv_transactions')
      let addressIndexes = fromResourceObjectsOfType(
        included,
        'address_indexes'
      )
        .sort((a, b) => a.index - b.index)
        .map(addressIndex => addressIndex.addressIndex)
      let amounts = fromResourceObjectsOfType(included, 'amounts')
      return {
        payment,
        paymentOutputs: fromResourceObjectsOfType(included, 'payment_outputs'),
        bsvTransaction,
        addressIndexes,
        amount: amounts[0]
      }
    }

    /**
     * Retrives the payment with the given payment id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} paymentId
     * @returns {object}
     */
    async getUserPayment (userId, paymentId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/payments/${paymentId}`)
      let { data, included } = fromJsonApiDataIncluding(json)
      const payment = fromResourceObject(data, 'payments')
      payment.paymentOutputs = fromResourceObjectsOfType(included, 'payment_outputs')
      return payment
    }

    /**
     * Updates the payment with the given payment id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} paymentId
     * @param {object} attributes
     * @param {bsv.Transaction} bsvTransaction
     * @returns {object}
     */
    async updateUserPaymentWithTransaction (
      userId,
      paymentId,
      attributes,
      bsvTransaction
    ) {
      let body = toJsonApiDataIncluding(
        toResourceObject(paymentId, 'payments', attributes),
        [toResourceObject(
          bsvTransaction.hash,
          'bsv_transactions',
          bsvTransaction
        )]
      )
      let json = await this._doPatchRequest(
        `/v1/users/${userId}/payments/${paymentId}`,
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'payments')
    }

    /**
     * Creates a deposit for the user with the given id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async createUserDeposit (userId, attributes) {
      const body = toJsonApiData(toNewResourceObject('deposits', attributes))
      const json = await this._doPostRequest(
        `/v1/users/${userId}/deposits`,
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'deposits')
    }

    /**
     * Retrives the deposit with the given deposit id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} depositId
     * @returns {object}
     */
    async getUserDeposit (userId, depositId) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/deposits/${depositId}`
      )
      return fromResourceObject(fromJsonApiData(json), 'deposits')
    }

    /**
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */
    async createUserWithdrawal (userId, attributes) {
      let body = toJsonApiData(toNewResourceObject('withdrawals', attributes))
      let json = await this._doPostRequest(
        `/v1/users/${userId}/withdrawals`,
        body
      )
      let { data, included } = fromJsonApiDataIncluding(json)
      let withdrawal = fromResourceObject(data, 'withdrawals')
      let [bsvTransaction] = fromResourceObjectsOfType(included, 'bsv_transactions')
      let addressIndexes = fromResourceObjectsOfType(
        included,
        'address_indexes'
      )
        .sort((a, b) => a.index - b.index)
        .map(addressIndex => addressIndex.addressIndex)
      return {
        withdrawal,
        bsvTransaction,
        addressIndexes
      }
    }

    /**
     * Retrives the withdrawal with the given withdrawal id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} withdrawalId
     * @returns {object}
     */
    async getUserWithdrawal (userId, withdrawalId) {
      const json = await this._doGetRequest(
        `/v1/users/${userId}/withdrawals/${withdrawalId}`
      )
      return fromResourceObject(fromJsonApiData(json), 'withdrawals')
    }

    /**
     * Updates the withdrawal with the given withdrawal id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} withdrawalId
     * @param {object} attributes
     * @param {object} transaction
     * @returns {object}
     */
    async updateUserWithdrawalWithTransaction (
      userId,
      withdrawalId,
      attributes,
      transaction
    ) {
      let body = toJsonApiDataIncluding(
        toResourceObject(withdrawalId, 'withdrawals', attributes),
        [toResourceObject(uuid.v1(), 'transactions', transaction)]
      )
      let json = await this._doPatchRequest(
        `/v1/users/${userId}/withdrawals/${withdrawalId}`,
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'withdrawals')
    }

    /**
     * Broadcasts the given bsv transaction. The transaction must be fully signed.
     *
     * @param {bsv.Transaction} bsvTransaction
     * @returns {object}
     */
    async broadcastTransaction (bsvTransaction) {
      const body = toJsonApiData(toResourceObject(
        bsvTransaction.hash,
        'bsv_transactions',
        bsvTransaction
      ))
      const json = await this._doPostRequest(
        '/v1/transactions/broadcast',
        body
      )
      return fromResourceObject(fromJsonApiData(json), 'txids')
    }

    /**
     * Broadcasts the given payment. It must include a fully signed transaction.
     *
     * @param {Payment} payment
     * @returns {object}
     */
    async broadcastPayment (payment) {
      const body = jsonSerializers.PaymentSerializer.serialize(payment)
      const json = await this._doPatchRequest(
        `/v1/payments/${payment.id}/broadcast`,
        body
      )
      return JsonDeserializer.deserialize(json)
    }

    /**
     * Retrieves the list of supported cryptocurrencies.
     *
     * @param {object} query
     * @returns {array}
     */
    async getSupportedCryptocurrencies (query = {}) {
      const json = await this._doGetRequest('/v1/currencies/crypto', query)
      return fromResourceObjectsOfType(fromJsonApiData(json), 'currencies')
    }

    /**
     * Retrieves the list of supported fiat currencies.
     *
     * @param {object} query
     * @returns {array}
     */
    async getSupportedFiatCurrencies (query = {}) {
      const json = await this._doGetRequest('/v1/currencies/fiat', query)
      return fromResourceObjectsOfType(fromJsonApiData(json), 'currencies')
    }

    /**
     * Looks up ui data for given user.
     *
     * @param {String} userId
     */
    async fetchUiData (userId) {
      const json = await this._doGetRequest(`/v1/users/${userId}/ui-data`)
      return fromResourceObject(fromJsonApiData(json), 'ui-data')
    }

    /**
     * Updates ui data for given user.
     *
     * @param {String} userId
     * @param {object} data
     */
    async updateUiData (userId, data) {
      const json = await this._doPatchRequest(`/v1/users/${userId}/ui-data`,
        toJsonApiData(toNewResourceObject('ui-data', data))
      )
      return fromResourceObject(fromJsonApiData(json), 'ui-data')
    }

    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */
    async _doGetRequest (endpoint, query = {}, accessToken = null) {
      let opts = {
        method: 'GET'
      }
      return this._doRequest(endpoint, opts, query, accessToken)
    }

    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} body - fetch request's body.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */
    async _doPostRequest (endpoint, body = {}, query = {}, accessToken = null) {
      let opts = {
        method: 'POST',
        body: JSON.stringify(body)
      }
      return this._doRequest(endpoint, opts, query, accessToken)
    }

    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} body - fetch request's body.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */
    async _doPatchRequest (endpoint, body = {}, accessToken = null) {
      let opts = {
        method: 'PATCH',
        body: JSON.stringify(body)
      }
      return this._doRequest(endpoint, opts, {}, accessToken)
    }

    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} body - fetch request's body.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */
    async _doPutRequest (endpoint, body = {}, accessToken = null) {
      let opts = {
        method: 'PUT',
        body: JSON.stringify(body)
      }
      return this._doRequest(endpoint, opts, {}, accessToken)
    }

    /**
     *
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} opts - fetch request options.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */
    async _doRequest (endpoint, opts = {}, query = {}, accessToken = null) {
      const url = this._appendQuery(`${API_REST_URI}/api${endpoint}`, query)
      let headers = {
        'Content-Type': 'application/vnd.api+json',
        Accept: 'application/vnd.api+json'
      }
      accessToken = accessToken === null
        ? await this.getValidAccessToken()
        : accessToken
      if (accessToken !== null) {
        headers['Authorization'] = `Bearer ${accessToken}`
      }
      const res = await fetch(url, { ...opts, headers })
      let json = await res.json()
      let { errors } = json
      if (errors instanceof Array) {
        let error = errors[0]
        if (error.status) {
          let { status, title, detail } = error
          throw new RestError(status, title, detail)
        }
        throw new Error(error.title)
      }
      return json
    }

    /**
     * @private
     * @param {string} url - base URL where query will be appended.
     * @param {object} query - URL query parameters.
     * @returns {string}
     */
    _appendQuery (url, query = {}) {
      if (Object.keys(query).length === 0) {
        return url
      }
      const { page, ...queryWithoutPage } = query
      if (page !== undefined) {
        for (const key in page) {
          queryWithoutPage[`page[${key}]`] = page[key]
        }
      }
      return `${url}?${queryString.stringify(queryWithoutPage)}`
    }

    /**
    *
    * Web location utilities.
    *
    */

    /**
     *
     */
    _getUrlQuery () {
      return queryString.parse(webLocation.search)
    }

    /**
     *
     * @param {string} uri - URI where the browser will be redirected to.
     */
    _redirectToUri (uri) {
      webLocation.href = uri
    }

    /**
    *
    * Web storage utilities.
    *
    */

    /**
     * @private
     * @returns {string}
     */
    _getRedirectUri () {
      return webStorage.getItem(OAUTH_REDIRECT_URI_KEY)
    }

    /**
     * @private
     * @param {string} redirectUri - OAuth redirect URI from authorization grant flow.
     * @returns {undefined}
     */
    _setRedirectUri (redirectUri) {
      webStorage.setItem(OAUTH_REDIRECT_URI_KEY, redirectUri)
    }

    /**
     * @private
     * @returns {undefined}
     */
    _clearRedirectUri () {
      webStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
    }

    /**
     * @private
     * @returns {undefined}
     */
    _getState () {
      return webStorage.getItem(OAUTH_STATE_KEY)
    }

    /**
     * @private
     * @param {string} state - OAuth state from authorization grant flow.
     * @returns {undefined}
     */
    _setState (state) {
      webStorage.setItem(OAUTH_STATE_KEY, state)
    }

    /**
     * @private
     * @returns {undefined}
     */
    _clearState () {
      webStorage.removeItem(OAUTH_STATE_KEY)
    }

    /**
     * Save internal cache of current user.
     */
    _setCurrentUser (userData) {
      webStorage.setItem(CURRENT_USER_CACHE_KEY, JSON.stringify(userData))
    }

    /**
     * Retrieve internal cache of current user
     *
     * @returns {object}
     */
    _getCurrentUser () {
      return JSON.parse(webStorage.getItem(CURRENT_USER_CACHE_KEY))
    }

    /**
     * Clears internal cache for current user.
     */
    _clearCurrentUser () {
      webStorage.removeItem(CURRENT_USER_CACHE_KEY)
    }

    /**
     * Retrieves the currently-set access token.
     *
     * @returns {string}
     */
    getAccessToken () {
      return webStorage.getItem(OAUTH_ACCESS_TOKEN_KEY)
    }

    /**
     * Sets the given access token.
     *
     * @param {string} accessToken - auth API access token
     * @returns {undefined}
     */
    setAccessToken (accessToken) {
      webStorage.setItem(OAUTH_ACCESS_TOKEN_KEY, accessToken)
    }

    /**
     * Clears the currently-set access token.
     *
     * @returns {undefined}
     */
    clearAccessToken () {
      webStorage.removeItem(OAUTH_ACCESS_TOKEN_KEY)
    }

    /**
     * Returns the currently-set token's expiration time in the following
     * format: 'YYYY-MM-DDTHH:mm:ssZ'.
     * For example, '2018-10-25T13:08:58-03:00'.
     *
     * @returns {string}
     */
    getExpirationTime () {
      return webStorage.getItem(OAUTH_EXPIRATION_TIME_KEY)
    }

    /**
     * Sets the currently-set token's expiration time. The argument must be
     * in the following format: 'YYYY-MM-DDTHH:mm:ssZ'.
     * For example, '2018-10-25T13:08:58-03:00'.
     *
     * @param {string} expirationTime
     * @returns {undefined}
     */
    setExpirationTime (expirationTime) {
      webStorage.setItem(OAUTH_EXPIRATION_TIME_KEY, expirationTime)
    }

    /**
     * Clears the currently-set access token's expiration time.
     *
     * @returns {undefined}
     */
    clearExpirationTime () {
      webStorage.removeItem(OAUTH_EXPIRATION_TIME_KEY)
    }

    /**
     * Retrieves the currently-set refresh token.
     *
     * @returns {string}
     */
    getRefreshToken () {
      return webStorage.getItem(OAUTH_REFRESH_TOKEN_KEY)
    }

    /**
     * Sets the given refresh token.
     *
     * @param {string} refreshToken - auth API refresh token
     * @returns {undefined}
     */
    setRefreshToken (refreshToken) {
      webStorage.setItem(OAUTH_REFRESH_TOKEN_KEY, refreshToken)
    }

    /**
     * Clears the currently-set refresh token.
     * @returns {undefined}
     */
    clearRefreshToken () {
      webStorage.removeItem(OAUTH_REFRESH_TOKEN_KEY)
    }

    /**
    *
    * Web crypto utilities.
    *
    */

    /**
     * @private
     * @param {string} key - HMAC key.
     * @param {string} message- HMAC message.
     * @returns {string}
     */
    static async _computeHmac256 (key, message) {
      const hash = sha256.hmac(
        Buffer.from(key),
        Buffer.from(message)
      )
      return Buffer.from(hash).toString('hex')
    }
  }

  return MoneyButtonClient
}
