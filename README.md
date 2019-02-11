# @moneybutton/api-client

![banner](assets/blue-white.png)

[![npm version](https://badge.fury.io/js/%40moneybutton%2Fclient.svg)](https://badge.fury.io/js/%40moneybutton%2Fclient)
[![standard-readme compliant](https://img.shields.io/badge/standard--readme-OK-green.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

> Money Button API Javascript Client.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Background

[Money Button](https://www.moneybutton.com) is a UI/UX and API layer for the blockchain which takes 0% transaction fees and makes Bitcoin SV easy for everyone, everywhere.

This project is a Javascript client providing a simple way of communicating with Money Button's API. For more information, please see our [docs](https://docs.moneybutton.com/).

## Install

```
yarn add -E @moneybutton/api-client
```

or

```
npm install --exact @moneybutton/api-client
```

## Usage

```
const MoneyButtonClient = require('@moneybutton/api-client')
const client = new MoneyButtonClient(
  '<your client identifier>',
  '<your client secret>'
)
```

## API

For in-detail API documentation, please see our automatically generated [docs](https://htmlpreview.github.io/?https://github.com/moneybutton/api-client/blob/master/docs/index.html).

## Maintainers

[@ealmansi](https://github.com/ealmansi)
[@hojarasca](https://github.com/hojarasca)
[@kevinejohn](https://github.com/kevinejohn)
[@ryanxcharles](https://github.com/ryanxcharles)

## Contribute

PRs accepted.

Small note: If editing the README, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

MIT © 2018 Yours Inc.
