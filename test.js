import { assert } from 'chai'
import {sha3} from 'ethereumjs-util'
import setup from './setup'
import MerkleTree, {
    checkProof, checkProofOrdered,
    merkleRoot, checkProofSolidityFactory, checkProofOrderedSolidityFactory
} from 'merkle-tree-solidity'
import {buildRandomNumbers, buildTreeWithSecrets,
  generateProofWithPartialMerkleTree
} from './index'

describe('MerkleTree with height=4', async () => {
    let merkleProof, eth, accounts, web3
    let checkProofSolidity

    // create a merkle tree
    const secrets = ['A', 'B', 'C', 'D']
    const numbers = buildRandomNumbers(secrets.length)
    const merkleTree = buildTreeWithSecrets(secrets, numbers)

    before(async () => {
        let result = await setup()
        merkleProof = result.merkleProof
        eth = result.eth
        accounts = result.accounts
        web3 = result.web3
        checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)
    })

    it('build the merkle tree', async () => {
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

    it('generate proof with partial tree', async () => {
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
