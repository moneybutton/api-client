import MoneyButtonConfigBuilder from '@moneybutton/config'

const config = new MoneyButtonConfigBuilder()
  .addValue('MONEY_BUTTON_API_REST_URI', process.env.MONEY_BUTTON_API_REST_URI)
  .addValue('MONEY_BUTTON_API_AUTH_URI', process.env.MONEY_BUTTON_API_AUTH_URI)
  .build()

export default config
