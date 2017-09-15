// import setup from './setup'
import MerkleTree, {
    checkProof, checkProofOrdered,
    merkleRoot, checkProofSolidityFactory, checkProofOrderedSolidityFactory
} from 'merkle-tree-solidity'
import {sha3} from 'ethereumjs-util'
import fs from 'fs'
import p from 'es6-promisify'
import TestRPC from 'ethereumjs-testrpc'
import solc from 'solc'
import Eth from 'ethjs-query'
import EthContract from 'ethjs-contract'
import Web3 from 'web3'
import HttpProvider from 'ethjs-provider-http'

const SOL_PATH = __dirname + '/src/'
const TESTRPC_PORT = 8545
const MNEMONIC = 'elegant ability lawn fiscal fossil general swarm trap bind require exchange ostrich'

// opts
// initTestRPC - if true, starts a testRPC server
// mnemonic - seed for accounts
// port - testrpc port
// noDeploy - if true, skip contract deployment
// testRPCProvider - http connection string for console testprc instance
// defaultAcct - the index of the default account
const setup = async function (opts) {
    opts = opts || {}
    const mnemonic = opts.mnemonic || MNEMONIC
    const testRPCServer = opts.testRPCServer
    const port = opts.port || TESTRPC_PORT
    const noDeploy = opts.noDeploy
    const defaultAcct = opts.defaultAcct ? opts.defaultAcct : 0

    // START TESTRPC PROVIDER
    let provider
    if (opts.testRPCProvider) {
        provider = new HttpProvider(opts.testRPCProvider)
    } else {
        provider = TestRPC.provider({
            mnemonic: mnemonic
        })
    }

    // START TESTRPC SERVER
    if (opts.testRPCServer) {
        console.log('setting up testrpc server')
        await p(TestRPC.server({
            mnemonic: mnemonic
        }).listen)(port)
    }

    // BUILD ETHJS ABSTRACTIONS
    const eth = new Eth(provider)
    const contract = new EthContract(eth)
    const accounts = await eth.accounts()

    // COMPILE THE CONTRACT
    const input = {
        'MerkleProof.sol': fs.readFileSync(SOL_PATH + 'MerkleProof.sol').toString(),
    }

    const output = solc.compile({sources: input}, 1)
    if (output.errors) {
        throw new Error(output.errors)
    }

    const abi = JSON.parse(output.contracts['MerkleProof.sol:MerkleProof'].interface)
    const bytecode = output.contracts['MerkleProof.sol:MerkleProof'].bytecode

    // PREPARE THE CONTRACT ABSTRACTION OBJECT
    const MerkleProof = contract(abi, bytecode, {
        from: accounts[defaultAcct],
        gas: 3000000
    })

    let txHash, receipt, merkleProof

    if (!noDeploy) {
        // DEPLOY THE ADMARKET CONTRACT
        txHash = await MerkleProof.new()
        await wait(1500)
        // USE THE ADDRESS FROM THE TX RECEIPT TO BUILD THE CONTRACT OBJECT
        receipt = await eth.getTransactionReceipt(txHash)
        merkleProof = MerkleProof.at(receipt.contractAddress);
    }

    // MAKE WEB3
    const web3 = new Web3()
    web3.setProvider(provider)
    web3.eth.defaultAccount = accounts[0]

    return {merkleProof, MerkleProof, eth, accounts, web3}
}

// async/await compatible setTimeout
// http://stackoverflow.com/questions/38975138/is-using-async-in-settimeout-valid
// await wait(2000)
const wait = ms => new Promise(resolve => setTimeout(resolve, ms))

const isPowerOf2 = (x) => ((x != 0) && !(x & (x - 1)))

const randomInt = (low, high) => Math.floor(Math.random() * (high - low) + low)

const randomIntInc = (low, high) => Math.floor(Math.random() * (high - low + 1) + low)

const randomIntArray = (size, low, high) => {
    var numbers = new Array(size)
    for (var i = 0; i < numbers.length; i++) {
        numbers[i] = randomInt(low, high)
    }
    return numbers
}
const buildRandomNumbers = (size) => randomIntArray(2 * size, 0, 1000)

// Extend MerkleTree
var MerkleTreeEx = function (layers, rebuilt) {
    if (rebuilt) {
        MerkleTree.call(this, layers[0], true)
    } else {
        this.layers = layers
        this.preserveOrder = true
        this.elements = layers[0]
    }
}

MerkleTreeEx.prototype = Object.create(MerkleTree.prototype)
MerkleTreeEx.prototype.constructor = MerkleTreeEx

MerkleTreeEx.prototype.toJson = function () {
    const layers = this.layers.map(layer => layer.map(e => e.toString('hex')))
    return JSON.stringify(layers)
}

MerkleTreeEx.fromJson = function (json) {
    const layers = JSON.parse(json)
    return new MerkleTreeEx(layers.map((layer) => layer.map(e => Buffer.from(e, 'hex'))), false)
}

MerkleTreeEx.prototype.partialMerkleTree = function () {
    return new MerkleTreeEx(this.layers.slice(1), false)
}

MerkleTreeEx.prototype.getLeaf = function (index) {
    var leafLevelIndex = 0
    if (index < 0 || index > this.layers[leafLevelIndex].length - 1) return null // index is out of array bounds

    return this.layers[leafLevelIndex][index]
}

const buildTree = (elements, hashed) => {
    if (!elements) return null

    // check if power of 2
    if (!isPowerOf2(elements.length)) {
        console.err('The number of leaves of the trees is restricted to powers of 2')
        return null
    }

    // create merkle tree
    // expects 32 byte buffers as inputs (no hex strings)
    // if using web3.sha3, convert first -> Buffer(web3.sha3('a'), 'hex')
    const leaves = hashed ? elements.map(e => sha3(e)) : elements

    // include the 'true' flag when generating the merkle tree
    return new MerkleTreeEx([leaves], true)
}

const buildTreeWithSecrets = (secrets, numbers) => {
    const n = secrets && numbers ? secrets.length : 0
    if (n === 0) return null
    const elements = new Array(2 * n)
    const randomNumbers = numbers || randomIntArray(n, 0, 1000)
    for (var i = 0; i < n; i++) {
        elements[i * 2] = sha3(secrets[i])
        elements[i * 2 + 1] = sha3(randomNumbers[i])
    }

    return buildTree(elements, false)
}

const generateProofWithPartialMerkleTree = (partialMerkleTree, index, secretNumber, randomNumber) => {
    const level1Index = Math.floor(index / 2) + 1
    const level1Node = partialMerkleTree.getLeaf(level1Index - 1)
    const secretLeaf = sha3(secretNumber)
    const partnerLeaf = sha3(randomNumber)

    const newProof = partialMerkleTree.getProofOrdered(level1Node, level1Index)
    newProof.unshift(partnerLeaf)

    return newProof
}


// Build a merkle tree with k secrets and k random numbers, then check proof
(async() => {
    let result = await setup({
        testRPCProvider: false
    })
    const merkleProof = result.merkleProof
    const eth = result.eth
    const accounts = result.accounts
    const web3 = result.web3
    const checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)

    // create merkle tree
    const secrets = ['A', 'B', 'C', 'D']
    const numbers = buildRandomNumbers(secrets.length)
    const merkleTree = buildTreeWithSecrets(secrets, numbers)

    // get the merkle root
    // returns 32 byte buffer
    const root = merkleTree.getRoot()

    // generate merkle proof
    // returns array of 32 byte buffers
    const hash = sha3(secrets[1])
    const index = 3
    const proof = merkleTree.getProofOrdered(hash, index)

    // check merkle proof in JS
    // returns bool
    console.log("checkProofOrdered: ", checkProofOrdered(proof, root, hash, index))

    // check merkle proof in Solidity
    // we can now safely pass in the buffers returned by previous methods
    const res = await checkProofSolidity(proof, root, hash, index) // -> true
    console.log("checkProofSolidity: " + res['0'])

    const partialMerkleTree = merkleTree.partialMerkleTree()

    const newProof = generateProofWithPartialMerkleTree(partialMerkleTree, 3, secrets[1], numbers[1])

    console.log("Proof with partial merkle tree: ")
    console.log(newProof)
    console.log("Proof in total merkle tree: ")
    console.log(proof)

    console.log("checkProofOrdered new: ", checkProofOrdered(newProof, root, hash, index))

    // check merkle proof in Solidity
    // we can now safely pass in the buffers returned by previous methods
    const res2 = await checkProofSolidity(newProof, root, hash, index) // -> true
    console.log("checkProofSolidity new: " + res2['0'])

    return merkleTree.toJson()
})().then((tree) => {
    console.log('Done');
    console.log("merkle tree in json:")
    console.log(tree)
    console.log("merkle tree from json")
    const newTree = MerkleTreeEx.fromJson(tree)
    console.log(newTree)
}).catch((error) => {
    console.error(error)
});
