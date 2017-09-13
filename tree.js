//import setup from './setup'
require("babel-polyfill");
import MerkleTree, { checkProof, checkProofOrdered,
	  merkleRoot, checkProofSolidityFactory, checkProofOrderedSolidityFactory
} from 'merkle-tree-solidity'
import { sha3 } from 'ethereumjs-util'

function randomInt (low, high) {
    return Math.floor(Math.random() * (high - low) + low);
}

function randomIntInc (low, high) {
    return Math.floor(Math.random() * (high - low + 1) + low);
}

function randomIntArray(size, low, high) {
    var numbers = new Array(size);
    for (var i = 0; i < numbers.length; i++) {
      numbers[i] = randomInt(low, high)
    }
    return numbers;
}

window.buildTree = function(size) {

//(async () => {
/*    let result = await setup({
		testRPCProvider: false
	})
    const merkleProof = result.merkleProof
    const    eth = result.eth
    const accounts = result.accounts
    const web3 = result.web3
    const checkProofSolidity = checkProofOrderedSolidityFactory(merkleProof.checkProofOrdered)
*/
	console.log(size);
	const values = randomIntArray(size, 0, 1000)

	console.log(values);
	// create merkle tree
	// expects 32 byte buffers as inputs (no hex strings)
	// if using web3.sha3, convert first -> Buffer(web3.sha3('a'), 'hex')
	const elements = values.map(e => sha3(e))

	// include the 'true' flag when generating the merkle tree
	const merkleTree = new MerkleTree(elements, true)

	// [same as above]
	// get the merkle root
	// returns 32 byte buffer
	const root = merkleTree.getRoot()

	// for convenience if only the root is desired
	// this creates a new MerkleTree under the hood
	// 2nd arg is "preserveOrder" flag
	const easyRoot = merkleRoot(elements, true)

	// generate merkle proof
	// 2nd argugment is the 1-n index of the element
	// returns array of 32 byte buffers
	const index = 1
	const proof = merkleTree.getProofOrdered(elements[0], index)

	// this is useful if you have duplicates in your tree
	//const elements2 = [3, 2, 3].map(e => sha3(e))
	//const index2 = 3
	//const proof2 = merkleTree.getProof(sha3(3), 3)

	// check merkle proof of ordered tree in JS
	// expects 1-n indexed element position as last param
	// returns bool
	//const index = 1
	var res = checkProofOrdered(proof, root, elements[0], index)
	// console.log(res)

	const layersHex = merkleTree.layers.map(layer => layer.map(e => '0x' + e.toString('hex')))

	// console.log(layersHex)

	return layersHex;

	// check merkle proof in Solidity
	// we can now safely pass in the buffers returned by previous methods
	//const res = await checkProofSolidity(proof, root, elements[0], index) // -> true
	//console.log(res)
//})();
}
