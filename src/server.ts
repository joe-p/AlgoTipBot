import express from 'express'
import Keyv from 'keyv'
import algosdk from 'algosdk'
import axios from 'axios'
import * as crypto from 'crypto'
import cors from 'cors'

namespace AlgoTipBot {
  export interface Callbacks {
    register?: (url: string) => Promise<void>
    verify?: () => Promise<void>,
  }

  export class VerificationServer {
    expressApp: express.Express
    keyv: Keyv
    callbacks: Callbacks
    algodClient: algosdk.Algodv2
    quicksigURL: string

    constructor (database: string, algodClient:algosdk.Algodv2, callbacks?: Callbacks) {
      this.expressApp = express()
      this.expressApp.use(express.urlencoded({ extended: true }))
      this.expressApp.use(express.json())
      this.expressApp.use(cors())

      this.keyv = new Keyv(database)
      this.keyv.on('error', err => console.log('Connection Error', err))
      this.callbacks = callbacks || {} as Callbacks
      this.algodClient = algodClient
      this.quicksigURL = 'http://localhost:3000'

      this.setRoutes()
    }

    async register (id: string | number, userAddress: string) {
      // generate quicksigk data and hash
      const account = algosdk.generateAccount()

      const suggestedParams = await algodClient.getTransactionParams().do()

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
          service: 'https://discord.gg/algorand',
          description: 'Proof of wallet ownership is needed for tipping functionality on the official Algorand discord server.',
        },

        post: {
          onSigned: 'http://localhost:3001/verify'
        },

        b64Txn: b64Txn,
        sigAddress: account.addr,
        userAddress: userAddress
      }

      const hash = crypto.createHash('sha256').update(JSON.stringify(metadata)).digest('hex')
      const sig = algosdk.signBytes(Buffer.from(hash, 'hex'), account.sk)

      const data = {
        metadata: metadata,
        hash: hash,
        sig: Buffer.from(sig).toString('base64')
      }

      axios
        .post(`${this.quicksigURL}/generate`, data)
        .then(res => {
          if (this.callbacks.register) {
            this.callbacks.register(`${this.quicksigURL}/${res.data}`)
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

        if (this.callbacks.verify) {
          this.callbacks.verify()
        }

        res.json({ msg: `Verified ${data.metadata.userAddress} belongs to ${data.metadata.auth.user}` })
      })
    }

    start (port: number, callback: () => void) {
      this.expressApp.listen(port, callback)
    }
  }
}

const algodServer = 'http://localhost'
const algodToken = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

const algodClient = new algosdk.Algodv2(algodToken, algodServer, 4001)

const server = new AlgoTipBot.VerificationServer('sqlite://db.sqlite', algodClient)
server.callbacks.register = async (hash: string) => console.log(hash)

server.start(3001, () => {
  console.log('Listening on port 3001')
  server.register('MonopolyMan#1876', 'D34DXBU2LDSFAYXD2WTGD3FVT2CFCQBTLHMFESUDC237SHSVODQNATP264')
})
