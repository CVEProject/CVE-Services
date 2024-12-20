/* eslint-disable no-unused-expressions */

const chai = require('chai')
chai.use(require('chai-http'))

const expect = chai.expect

const constants = require('../constants.js')
const app = require('../../../src/index.js')
const helpers = require('../helpers.js')

const requestLength = 1
const shortName = 'win_5'
const cveYear = '2023'
const batchType = 'non-sequential'

describe('Testing PUT ERLCheck field', () => {
  let cveId
  before(async () => {
    cveId = await helpers.cveIdReserveHelper(requestLength, cveYear, shortName, batchType)
    await helpers.cveRequestAsCnaHelper(cveId)
    console.log('HEre')
  })
  context('ERL PUT Check Tests', () => {
    it('PUT CVE that is ERL Checked with correct details', async () => {
      await chai.request(app)
        .put(`/api/cve/${cveId}/cna?erlcheck=true`)
        .set(constants.nonSecretariatUserHeaders)
        .send(constants.enrichedCve)
        .then((res, err) => {
        // Safety Expect
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
        })
    })

    it('PUT CVE that is ERL checked with the incorrect details', async () => {
      await chai.request(app)
        .put(`/api/cve/${cveId}/cna?erlcheck=true`)
        .set(constants.nonSecretariatUserHeaders)
        .send(constants.testCve)
        .then((res, err) => {
        // Safety Expect
          expect(res).to.have.status(403)
        })
    })

    it('PUT CVE that is ERL is false with correct details', async () => {
      await chai.request(app)
        .put(`/api/cve/${cveId}/cna?erlcheck=false`)
        .set(constants.nonSecretariatUserHeaders)
        .send(constants.enrichedCve)
        .then((res, err) => {
        // Safety Expect
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
        })
    })

    it('PUT CVE that is ERL is false with the incorrect details', async () => {
      await chai.request(app)
        .put(`/api/cve/${cveId}/cna?erlcheck=false`)
        .set(constants.nonSecretariatUserHeaders)
        .send(constants.testCve)
        .then((res, err) => {
        // Safety Expect
          expect(res).to.have.status(200)
        })
    })

    it('PUT CVE that is ERL is null with correct details', async () => {
      await chai.request(app)
        .put(`/api/cve/${cveId}/cna?erlcheck=null`)
        .set(constants.nonSecretariatUserHeaders)
        .send(constants.enrichedCve)
        .then((res, err) => {
        // Safety Expect
          expect(err).to.be.undefined
          expect(res).to.have.status(400)
        })
    })
  })
})
