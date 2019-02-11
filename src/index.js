import Window from 'window'
import crypto from '@trust/webcrypto'
import localStorage from 'localstorage-memory'

import AuthError from './auth-error'
import getMoneyButtonClient from './get-money-button-client'
import RestError from './rest-error'

const MoneyButtonClient = getMoneyButtonClient(
  localStorage,
  crypto,
  new Window().location
)

export {
  MoneyButtonClient,
  AuthError,
  RestError
}
