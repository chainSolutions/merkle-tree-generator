// import setup from './setup'
import MerkleTree, { checkProof, checkProofOrdered,
      merkleRoot, checkProofSolidityFactory, checkProofOrderedSolidityFactory
} from 'merkle-tree-solidity'
import { sha3 } from 'ethereumjs-util'
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

  const output = solc.compile({ sources: input }, 1)
  if (output.errors) { throw new Error(output.errors) }

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

  return  { merkleProof, MerkleProof, eth, accounts, web3 }
}

// async/await compatible setTimeout
// http://stackoverflow.com/questions/38975138/is-using-async-in-settimeout-valid
// await wait(2000)
const wait = ms => new Promise(resolve => setTimeout(resolve, ms))

const randomInt = (low, high) => Math.floor(Math.random() * (high - low) + low)

const randomIntInc = (low, high) => Math.floor(Math.random() * (high - low + 1) + low)

const randomIntArray = (size, low, high) => {
    var numbers = new Array(size)
    for (var i = 0; i < numbers.length; i++) {
      numbers[i] = randomInt(low, high)
    }
    return numbers
}

const buildRandomNumbers = (size) => randomIntArray(2*size, 0, 1000)

const buildTree = (numbers) => {
    // create merkle tree
    // expects 32 byte buffers as inputs (no hex strings)
    // if using web3.sha3, convert first -> Buffer(web3.sha3('a'), 'hex')
    const elements = numbers.map(e => sha3(e))

    // include the 'true' flag when generating the merkle tree
    return new MerkleTree(elements, true)
}

const buildTreeWithSecrets = (secrets, numbers) => {
    const n = secrets && numbers ? secrets.length : 0
    if (n === 0 ) return null
    const elements = new Array(2*n)
    const randomNumbers = numbers || randomIntArray(n, 0, 1000)
    for (var i=0; i<n; i++) {
        elements[i*2] = sha3(secrets[i])
        elements[i*2+1] = sha3(randomNumbers[i])
    }

    return new MerkleTree(elements, true)
}

const generateProofWithLevel1Nodes = (nodes, numbers, secret, index) => {
    // generate merkle proof with one level higher
    const level1Nodes = nodes
    const level1Tree = new MerkleTree(level1Nodes, true)

    const level1Index = Math.floor(index/2) + 1
    const level1Node = level1Nodes[level1Index-1]
    const leafLeft = sha3(secret)
    const leafRight = sha3(numbers[level1Index-1])

    // const proof2 = level1Tree.getProofOrdered(level1Node, 2)
    const newProof = level1Tree.getProofOrdered(level1Node, level1Index)
    newProof.unshift(leafRight)

    return newProof
}

// Build a merkle tree with 2*k random numbers, then check proof
(async () => {
    let result = await setup({
        testRPCProvider: false
    })
    const merkleProof = result.merkleProof
    const eth = result.eth
    const accounts = result.accounts
    const web3 = result.web3
    const checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)

    // create merkle tree
    const elements = buildRandomNumbers(2)
    const merkleTree = buildTree(elements)

    // get the merkle root
    // returns 32 byte buffer
    const root = merkleTree.getRoot()

    // generate merkle proof
    // returns array of 32 byte buffers
    const hash = sha3(elements[0])
    const proof = merkleTree.getProof(hash)
    const index = 1

    // check merkle proof in JS
    // returns bool
    console.log("checkProofOrdered: ", checkProofOrdered(proof, root, hash, index))

    // check merkle proof in Solidity
    // we can now safely pass in the buffers returned by previous methods
    const res = await checkProofSolidity(proof, root, hash, index) // -> true
    console.log("checkProofSolidity: " + res['0'])

    return merkleTree.layers.map(layer => layer.map(e => '0x' + e.toString('hex')))
})().then((tree) => {
    console.log('Done');
    console.log("merkle tree:")
    console.log(tree)
}).catch((error) => {
    console.error(error)
});


// Build a merkle tree with k secrets and k random numbers, then check proof
(async () => {
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

    const newProof = generateProofWithLevel1Nodes(merkleTree.layers[1], numbers, secrets[1], 3)

    console.log("Proof with level one nodes: ")
    console.log(newProof)
    console.log("Proof in original merkle tree: ")
    console.log(proof)

    console.log("checkProofOrdered new: ", checkProofOrdered(newProof, root, hash, index))

    // check merkle proof in Solidity
    // we can now safely pass in the buffers returned by previous methods
    const res2 = await checkProofSolidity(newProof, root, hash, index) // -> true
    console.log("checkProofSolidity new: " + res2['0'])

    return merkleTree.layers.map(layer => layer.map(e => '0x' + e.toString('hex')))
})().then((tree) => {
    console.log('Done');
    console.log("merkle tree:")
    console.log(tree)
}).catch((error) => {
    console.error(error)
});
