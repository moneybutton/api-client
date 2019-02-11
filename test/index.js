import should from 'should'

import { getClient } from './util'

describe('MoneyButtonClient', () => {
  let client

  beforeEach(() => {
    client = getClient()
  })

  it('should exist', async () => {
    should.exist(client)
  })

  it('should not be logged in by default', async () => {
    let isLoggedIn = await client.isLoggedIn()
    isLoggedIn.should.be.false()
  })
})
