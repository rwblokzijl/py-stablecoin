from Core.trustchain import TrustChain
from nacl import signing
import os

if __name__ == '__main__':
	a_SkPk = signing.SigningKey.generate()
	a_Pk = a_SkPk.verify_key
	alice = TrustChain(a_SkPk)

	b_SkPk = signing.SigningKey.generate()
	b_Pk = b_SkPk.verify_key
	bob = TrustChain(b_SkPk)

	a_genesis_block = alice.create_genesis_block()

	TrustChain.verify_block(a_genesis_block)

	bytes_32 = os.urandom(32)
	prop_block = alice.propose_tx_block(bytes_32, bytes(b_Pk), bytes_32, 111, 222, 333)

	TrustChain.verify_tx_proposal_block(prop_block)

	signed_block = bob.sign_proposal_block(prop_block)

	TrustChain.verify_block(signed_block)
