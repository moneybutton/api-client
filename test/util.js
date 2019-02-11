import HttpStatus from 'http-status-codes'
import nock from 'nock'
import path from 'path'

import config from './config'
import { MoneyButtonClient } from '..'

const API_REST_URI = config.get('MONEY_BUTTON_API_REST_URI')
const CLIENT_IDENTIFIER = config.get('MONEY_BUTTON_PUBLIC_CLIENT_IDENTIFIER')

export function getClient () {
  return new MoneyButtonClient(CLIENT_IDENTIFIER)
}

export function getMockApi () {
  return nock(API_REST_URI)
}

export function replyWithResource (request, resource) {
  let filePath = path.resolve(__dirname, 'resources', resource)
  let headers = { 'Content-Type': 'application/vnd.api+json' }
  request.replyWithFile(HttpStatus.OK, filePath, headers)
  return request
}

export async function shouldEventuallyThrow (fn) {
  await fn().should.be.rejected()
}
