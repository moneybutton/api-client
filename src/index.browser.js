import AuthError from './auth-error'
import getMoneyButtonClient from './get-money-button-client'
import RestError from './rest-error'

const MoneyButtonClient = getMoneyButtonClient(
  window.localStorage,
  window.crypto,
  window.location
)

export {
  MoneyButtonClient,
  AuthError,
  RestError
}
