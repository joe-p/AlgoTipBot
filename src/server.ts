import express from 'express'
import Keyv from 'keyv'
import algosdk from 'algosdk'
import axios from 'axios'
import * as crypto from 'crypto'
import cors from 'cors'
import { EventEmitter } from 'events'

export namespace AlgoTipBot {
  export interface VerificationServerOptions {
    database: string
    algodClient: algosdk.Algodv2
    quicksigURL: string
    account: algosdk.Account
    service: string
    description: string
    url: string
  }

  export class VerificationServer {
    expressApp: express.Express
    keyv: Keyv
    algodClient: algosdk.Algodv2
    quicksigURL: string
    account: algosdk.Account
    service: string
    description: string
    url: string
    events: EventEmitter

    constructor (options: VerificationServerOptions) {
      this.expressApp = express()
      this.expressApp.use(express.urlencoded({ extended: true }))
      this.expressApp.use(express.json())
      this.expressApp.use(cors())

      this.keyv = new Keyv(options.database)
      this.keyv.on('error', err => console.log('Connection Error', err))

      this.algodClient = options.algodClient
      this.quicksigURL = options.quicksigURL
      this.account = options.account
      this.service = options.service
      this.description = options.description
      this.url = options.url
      this.events = new EventEmitter()

      this.setRoutes()
    }

    async register (id: string, userAddress: string, callbackFunction?: (url: string) => Promise<void>) {
      const dbAddress = await this.keyv.get(id)

      if (dbAddress === userAddress) {
        this.events.emit('verify', id, userAddress)
        return
      }

      const suggestedParams = await this.algodClient.getTransactionParams().do()

      const payObj = {
        suggestedParams: { ...suggestedParams, lastRound: 1, firstRound: 2 },
        from: userAddress,
        to: userAddress,
        amount: 0
      }

      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject(payObj)
      const b64Txn = Buffer.from(txn.toByte()).toString('base64')

      const metadata = {
        auth: {
          isAuth: true,
          user: id,
          service: this.service,
          description: this.description
        },

        post: {
          onSigned: `${this.url}/verify`
        },

        b64Txn: b64Txn,
        sigAddress: this.account.addr,
        userAddress: userAddress
      }

      const hash = crypto.createHash('sha256').update(JSON.stringify(metadata)).digest('hex')
      const sig = algosdk.signBytes(Buffer.from(hash, 'hex'), this.account.sk)

      const data = {
        metadata: metadata,
        hash: hash,
        sig: Buffer.from(sig).toString('base64')
      }

      axios
        .post(`${this.quicksigURL}/generate`, data)
        .then(res => {
          if (callbackFunction) {
            callbackFunction(`${this.quicksigURL}/${res.data}`)
          }
        })
        .catch(error => {
          console.error(error)
        })
    }

    setRoutes () {
      // POST /verify from QuickSig with data and b64SignedTxn
      // verify txn was signed by user address
      // add to database
      // run callback
      this.expressApp.post('/verify', (req, res, next) => {
        const data = req.body.data
        const b64SignedTxn = req.body.b64SignedTxn

        const sTxn = algosdk.decodeSignedTransaction(Buffer.from(b64SignedTxn, 'base64'))
        const txn = algosdk.decodeUnsignedTransaction(Buffer.from(data.metadata.b64Txn, 'base64'))

        const conds = [] as Array<boolean>
        conds.push(txn.toString() === sTxn.txn.toString())
        conds.push(!sTxn.sgnr) // The signer is the same as the from address
        conds.push(algosdk.encodeAddress(txn.from.publicKey) === data.metadata.userAddress)

        if (conds.includes(false)) {
          res.sendStatus(500)
          return
        }

        const user = data.metadata.auth.user
        const userAddress = data.metadata.userAddress

        this.keyv.set(user, userAddress)
        this.events.emit('verify', user, userAddress)

        res.json({ msg: `Verified ${userAddress} belongs to ${user}` })
      })
    }

    start (port: number, callback: () => void) {
      this.expressApp.listen(port, callback)
    }
  }
}

export default AlgoTipBot
