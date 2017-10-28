import { assert } from 'chai'
import {sha3} from 'ethereumjs-util'
import setup from './setup'
import MerkleTree, {
    checkProof, checkProofOrdered,
    merkleRoot, checkProofSolidityFactory, checkProofOrderedSolidityFactory
} from 'merkle-tree-solidity'
import {buildRandomNumbers, buildRandomSecrets, buildTreeWithSecrets,
  generateProofWithPartialMerkleTree
} from './index'

describe('Build randoms and secrets', () => {
    it('invaliad size should return null',  () => {
        assert.isNull(buildRandomNumbers(-100))
        assert.isNull(buildRandomNumbers(-1))
        assert.isNull(buildRandomNumbers(0))


        assert.isNull(buildRandomSecrets(-100))
        assert.isNull(buildRandomSecrets(-1))
        assert.isNull(buildRandomSecrets(0))
    })

    it('check generated nummbers and secrets',  () => {
        let randoms = buildRandomNumbers(2)
        assert.isOk(randoms)
        assert.isTrue(randoms instanceof Array)
        assert.equal(2, randoms.length)
        for (let i=0; i<randoms.length; i++) {
            assert.isTrue(typeof randoms[i] == 'number')
        }

        randoms = buildRandomNumbers(10)
        assert.isOk(randoms)
        assert.isTrue(randoms instanceof Array)
        assert.equal(10, randoms.length)
        for (let i=0; i<randoms.length; i++) {
            assert.isTrue(typeof randoms[i] == 'number')
        }

        let secrets = buildRandomSecrets(2)
        assert.isOk(secrets)
        assert.isTrue(secrets instanceof Array)
        assert.equal(2, secrets.length)
        for (let i=0; i<secrets.length; i++) {
            assert.isTrue(typeof secrets[i] == 'string')
        }

        secrets = buildRandomSecrets(10)
        assert.isOk(secrets)
        assert.isTrue(secrets instanceof Array)
        assert.equal(10, secrets.length)
        for (let i=0; i<secrets.length; i++) {
            assert.isTrue(typeof secrets[i] == 'string')
        }
    })
})

describe('MerkleTree with leaves!=2^n', () => {
    let secrets
    let numbers
    let merkleTree

    before(() => {
        secrets = ['A', 'B', 'C']
        numbers = buildRandomNumbers(secrets.length)
        merkleTree = buildTreeWithSecrets(secrets, numbers)
    })


    it('should return null',  () => {
        assert.isNull(merkleTree)
    })
})

describe('MerkleTree with height=4', async () => {
    let merkleProof, eth, accounts, web3
    let checkProofSolidity

    const height = 4

    const size = Math.pow(2, height-1)
    const halfSize = size/2
    // create a merkle tree
    const secrets = buildRandomSecrets(halfSize)
    const numbers = buildRandomNumbers(halfSize)
    const merkleTree = buildTreeWithSecrets(secrets, numbers)

    before(async () => {
        let result = await setup()
        merkleProof = result.merkleProof
        eth = result.eth
        accounts = result.accounts
        web3 = result.web3
        checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)
    })

    it('generate and check proof with total merkle tree', async () => {
        assert.isOk(numbers)
        assert.isOk(merkleTree)

        // get the merkle root
        const root = merkleTree.getRoot()

        for (let i=0; i<4; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const hash = sha3(secret)

            // generate merkle proof
            const proof = merkleTree.getProofOrdered(hash, index)

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            // we can now safely pass in the buffers returned by previous methods
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })

    it('generate and check proof with partial merkle tree', async () => {
        const partialMerkleTree = merkleTree.partialMerkleTree()

        for (let i=0; i<4; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const number = numbers[i]
            const hash = sha3(secret)
            const proof = generateProofWithPartialMerkleTree(partialMerkleTree, index, secret, number)

            const root = partialMerkleTree.getRoot()

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })
})

describe('MerkleTree with height=3', async () => {
    let merkleProof, eth, accounts, web3
    let checkProofSolidity

    const height = 3

    const size = Math.pow(2, height-1)
    const halfSize = size/2
    // create a merkle tree
    const secrets = buildRandomSecrets(halfSize)
    const numbers = buildRandomNumbers(halfSize)
    const merkleTree = buildTreeWithSecrets(secrets, numbers)

    before(async () => {
        let result = await setup()
        merkleProof = result.merkleProof
        eth = result.eth
        accounts = result.accounts
        web3 = result.web3
        checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)
    })

    it('generate and check proof with total merkle tree', async () => {
        assert.isOk(numbers)
        assert.isOk(merkleTree)

        // get the merkle root
        const root = merkleTree.getRoot()

        for (let i=0; i<halfSize; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const hash = sha3(secret)

            // generate merkle proof
            const proof = merkleTree.getProofOrdered(hash, index)

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            // we can now safely pass in the buffers returned by previous methods
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })

    it('generate and check proof with partial merkle tree', async () => {
        const partialMerkleTree = merkleTree.partialMerkleTree()

        for (let i=0; i<halfSize; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const number = numbers[i]
            const hash = sha3(secret)
            const proof = generateProofWithPartialMerkleTree(partialMerkleTree, index, secret, number)

            const root = partialMerkleTree.getRoot()

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })
})

describe('MerkleTree with height=2', async () => {
    let merkleProof, eth, accounts, web3
    let checkProofSolidity

    const height = 2

    const size = Math.pow(2, height-1)
    const halfSize = size/2
    // create a merkle tree
    const secrets = buildRandomSecrets(halfSize)
    const numbers = buildRandomNumbers(halfSize)
    const merkleTree = buildTreeWithSecrets(secrets, numbers)

    before(async () => {
        let result = await setup()
        merkleProof = result.merkleProof
        eth = result.eth
        accounts = result.accounts
        web3 = result.web3
        checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)
    })

    it('generate and check proof with total merkle tree', async () => {
        assert.isOk(numbers)
        assert.isOk(merkleTree)

        // get the merkle root
        const root = merkleTree.getRoot()

        for (let i=0; i<halfSize; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const hash = sha3(secret)

            // generate merkle proof
            const proof = merkleTree.getProofOrdered(hash, index)

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            // we can now safely pass in the buffers returned by previous methods
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })

    it('generate and check proof with partial merkle tree', async () => {
        const partialMerkleTree = merkleTree.partialMerkleTree()

        for (let i=0; i<halfSize; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const number = numbers[i]
            const hash = sha3(secret)
            const proof = generateProofWithPartialMerkleTree(partialMerkleTree, index, secret, number)

            const root = partialMerkleTree.getRoot()

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })
})

describe('MerkleTree with height=10', async () => {
    let merkleProof, eth, accounts, web3
    let checkProofSolidity

    const height = 10

    const size = Math.pow(2, height-1)
    const halfSize = size/2
    // create a merkle tree
    const secrets = buildRandomSecrets(halfSize)
    const numbers = buildRandomNumbers(halfSize)
    const merkleTree = buildTreeWithSecrets(secrets, numbers)

    before(async () => {
        let result = await setup()
        merkleProof = result.merkleProof
        eth = result.eth
        accounts = result.accounts
        web3 = result.web3
        checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)
    })

    it('generate and check proof with total merkle tree', async () => {
        assert.isOk(numbers)
        assert.isOk(merkleTree)

        // get the merkle root
        const root = merkleTree.getRoot()

        for (let i=0; i<halfSize; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const hash = sha3(secret)

            // generate merkle proof
            const proof = merkleTree.getProofOrdered(hash, index)

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            // we can now safely pass in the buffers returned by previous methods
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })

    it('generate and check proof with partial merkle tree', async () => {
        const partialMerkleTree = merkleTree.partialMerkleTree()

        for (let i=0; i<halfSize; i++) {
            const index = 2*i+1
            const secret = secrets[i]
            const number = numbers[i]
            const hash = sha3(secret)
            const proof = generateProofWithPartialMerkleTree(partialMerkleTree, index, secret, number)

            const root = partialMerkleTree.getRoot()

            // check merkle proof in JS
            assert.isTrue(checkProofOrdered(proof, root, hash, index))

            // check merkle proof in Solidity
            assert.isTrue((await checkProofSolidity(proof, root, hash, index))[0])
        }
    })
})
