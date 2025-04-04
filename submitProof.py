import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware  # Necessary for POA chains
from eth_account.messages import encode_defunct  # 添加这行导入



def merkle_assignment():
    """
        The only modifications you need to make to this method are to assign
        your "random_leaf_index" and uncomment the last line when you are
        ready to attempt to claim a prime. You will need to complete the
        methods called by this method to generate the proof.
    """
    # Generate the list of primes as integers
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)

    # Create a version of the list of primes in bytes32 format
    leaves = convert_leaves(primes)

    # Build a Merkle tree using the bytes32 leaves as the Merkle tree's leaves
    tree = build_merkle(leaves)

    # Select a random leaf and create a proof for that leaf
    random_leaf_index = random.randint(1, len(primes) - 1)  # 避开索引0
    proof = prove_merkle(tree, random_leaf_index)

    # This is the same way the grader generates a challenge for sign_challenge()
    challenge = ''.join(random.choice(string.ascii_letters) for i in range(32))
    # Sign the challenge to prove to the grader you hold the account
    addr, sig = sign_challenge(challenge)

    if sign_challenge_verify(challenge, addr, sig):
        tx_hash = '0x'
        # TODO, when you are ready to attempt to claim a prime (and pay gas fees),
        #  complete this method and run your code with the following line un-commented
        tx_hash = send_signed_msg(proof, leaves[random_leaf_index])
        print(f"Transaction hash: {tx_hash}")


def generate_primes(num_primes):
    """
        Function to generate the first 'num_primes' prime numbers
        returns list (with length n) of primes (as ints) in ascending order
    """
    primes_list = []

    #TODO YOUR CODE HERE
    num = 2
    while len(primes_list) < num_primes:
        is_prime = True
        for p in primes_list:
            if p * p > num:
                break
            if num % p == 0:
                is_prime = False
                break
        if is_prime:
            primes_list.append(num)
        num += 1

    return primes_list


def convert_leaves(primes_list):
    """
        Converts the leaves (primes_list) to bytes32 format
        returns list of primes where list entries are bytes32 encodings of primes_list entries
    """

    # TODO YOUR CODE HERE

    return [prime.to_bytes(32, 'big') for prime in primes_list]


def build_merkle(leaves):
    """
        Function to build a Merkle Tree from the list of prime numbers in bytes32 format
        Returns the Merkle tree (tree) as a list where tree[0] is the list of leaves,
        tree[1] is the parent hashes, and so on until tree[n] which is the root hash
        the root hash produced by the "hash_pair" helper function
    """

    #TODO YOUR CODE HERE
    tree = [leaves]
    current_level = leaves
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i+1 < len(current_level) else left
            next_level.append(hash_pair(left, right))
        tree.append(next_level)
        current_level = next_level

    return tree


def prove_merkle(merkle_tree, random_indx):
    """
        Takes a random_index to create a proof of inclusion for and a complete Merkle tree
        as a list of lists where index 0 is the list of leaves, index 1 is the list of
        parent hash values, up to index -1 which is the list of the root hash.
        returns a proof of inclusion as list of values
    """
    merkle_proof = []
    # TODO YOUR CODE HERE
    current_index = random_indx
    
    for level in merkle_tree[:-1]:
        sibling_index = current_index + 1 if current_index % 2 == 0 else current_index - 1
        if sibling_index < len(level):
            merkle_proof.append(level[sibling_index])
        current_index = current_index // 2

    return merkle_proof


def sign_challenge(challenge):
    """
        Takes a challenge (string)
        Returns address, sig
        where address is an ethereum address and sig is a signature (in hex)
        This method is to allow the auto-grader to verify that you have
        claimed a prime
    """
    acct = get_account()

    addr = acct.address
    eth_sk = acct.key

    # TODO YOUR CODE HERE    
    message = encode_defunct(text=challenge)
    
    signed_message = eth_account.Account.sign_message(message, private_key=eth_sk)
    
    return addr, signed_message.signature.hex()



def send_signed_msg(proof, random_leaf):
    """
        Takes a Merkle proof of a leaf, and that leaf (in bytes32 format)
        builds signs and sends a transaction claiming that leaf (prime)
        on the contract
    """
    chain = 'bsc'

    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)

    # TODO YOUR CODE HERE
    contract = w3.eth.contract(address=address, abi=abi)
    nonce = w3.eth.get_transaction_count(acct.address)
    
    tx = contract.functions.submit(proof, random_leaf).build_transaction({
        'chainId': 97,  # BSC chain ID
        'gas': 200000, 
        'gasPrice': w3.to_wei('20', 'gwei'), 
        'nonce': nonce,
    })
    
    # 3. 签名交易 - 兼容多种Web3.py版本
    # 首先尝试使用Web3.py v6+的方式
    signed_tx = w3.eth.account.sign_transaction(tx, acct.key)
    
    # 4. 发送交易 - 兼容多种Web3.py版本
    try:
        # 尝试Web3.py v6+的方式 ('raw_transaction')
        if hasattr(signed_tx, 'raw_transaction'):
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        # 尝试Web3.py v5及以下的方式 ('rawTransaction')
        elif hasattr(signed_tx, 'rawTransaction'):
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        # 如果以上都不行，尝试解析为字典
        else:
            # 转换为字典并寻找合适的属性
            tx_dict = vars(signed_tx) if hasattr(signed_tx, '__dict__') else signed_tx
            
            if 'rawTransaction' in tx_dict:
                tx_hash = w3.eth.send_raw_transaction(tx_dict['rawTransaction'])
            elif 'raw_transaction' in tx_dict:
                tx_hash = w3.eth.send_raw_transaction(tx_dict['raw_transaction'])
            else:
                # 最后的尝试：直接打印签名交易对象并报错
                print(f"签名交易对象的属性: {dir(signed_tx)}")
                print(f"签名交易对象: {signed_tx}")
                raise ValueError("无法找到交易的原始数据。请检查Web3.py版本兼容性。")
    
    except Exception as e:
        print(f"发送交易时出错: {e}")
        # 尝试使用另一种方法
        try:
            # 直接使用eth_account库的方式
            from eth_account import Account
            import eth_account
            
            # 重新签名
            signed_tx2 = Account.sign_transaction(tx, acct.key)
            
            # 打印签名对象信息进行调试
            print(f"Alternate签名对象类型: {type(signed_tx2)}")
            print(f"Alternate签名对象属性: {dir(signed_tx2)}")
            
            # 尝试所有可能的属性名
            if hasattr(signed_tx2, 'rawTransaction'):
                tx_hash = w3.eth.send_raw_transaction(signed_tx2.rawTransaction)
            elif hasattr(signed_tx2, 'raw_transaction'):
                tx_hash = w3.eth.send_raw_transaction(signed_tx2.raw_transaction)
            else:
                raise ValueError("仍然无法找到交易的原始数据")
                
        except Exception as e2:
            print(f"第二次尝试也失败: {e2}")
            return '0x'  # 返回空哈希表示失败
    
    # 5. 等待交易确认
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status == 1:
            print(f"Transaction successful! Hash: {tx_hash.hex()}")
        else:
            print("Transaction failed!")
        
        return tx_hash.hex()
    except Exception as e:
        print(f"等待交易确认时出错: {e}")
        # 即使等待确认失败，仍返回交易哈希
        if hasattr(tx_hash, 'hex'):
            return tx_hash.hex()
        return str(tx_hash)






# Helper functions that do not need to be modified
def connect_to(chain):
    """
        Takes a chain ('avax' or 'bsc') and returns a web3 instance
        connected to that chain.
    """
    if chain not in ['avax','bsc']:
        print(f"{chain} is not a valid option for 'connect_to()'")
        return None
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"  # AVAX C-chain testnet
    else:
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"  # BSC testnet
    w3 = Web3(Web3.HTTPProvider(api_url))
    # inject the poa compatibility middleware to the innermost layer
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    return w3


def get_account():
    """
        Returns an account object recovered from the secret key
        in "sk.txt"
    """
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath('sk.txt'), 'r') as f:
        sk = f.readline().rstrip()
    if sk[0:2] == "0x":
        sk = sk[2:]
    return eth_account.Account.from_key(sk)


def get_contract_info(chain):
    """
        Returns a contract address and contract abi from "contract_info.json"
        for the given chain
    """
    contract_file = Path(__file__).parent.absolute() / "contract_info.json"
    if not contract_file.is_file():
        contract_file = Path(__file__).parent.parent.parent / "tests" / "contract_info.json"
    with open(contract_file, "r") as f:
        d = json.load(f)
        d = d[chain]
    return d['address'], d['abi']


def sign_challenge_verify(challenge, addr, sig):
    """
        Helper to verify signatures, verifies sign_challenge(challenge)
        the same way the grader will. No changes are needed for this method
    """
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)

    if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == addr:
        print(f"Success: signed the challenge {challenge} using address {addr}!")
        return True
    else:
        print(f"Failure: The signature does not verify!")
        print(f"signature = {sig}\naddress = {addr}\nchallenge = {challenge}")
        return False


def hash_pair(a, b):
    """
        The OpenZeppelin Merkle Tree Validator we use sorts the leaves
        https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol#L217
        So you must sort the leaves as well

        Also, hash functions like keccak are very sensitive to input encoding, so the solidity_keccak function is the function to use

        Another potential gotcha, if you have a prime number (as an int) bytes(prime) will *not* give you the byte representation of the integer prime
        Instead, you must call int.to_bytes(prime,'big').
    """
    if a < b:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [a, b])
    else:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [b, a])


if __name__ == "__main__":
    merkle_assignment()
