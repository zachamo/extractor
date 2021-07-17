"""NEM Extractor Script"""

import argparse
import os
import glob
import struct
import tqdm
import pandas as pd
import pdb
import pickle
import re
import hashlib
import base64
from tqdm import tqdm
from binascii import hexlify, unhexlify


# describe the structure of block entity bytes for unpacking

HEADER_FORMAT = {
    'size': 'I',
    'reserved_1': 'I',
    'signature': '64s',
    'signer_public_key': '32s',
    'reserved_2': 'I',
    'version': 'B',
    'network': 'B',
    'type': '2s',
    'height': 'Q',
    'timestamp': 'Q',
    'difficulty': 'Q',
    'generation_hash_proof': '80s',
    'previous_block_hash': '32s',
    'transactions_hash': '32s',
    'receipts_hash': '32s',
    'state_hash': '32s',
    'beneficiary_address': '24s',
    'fee_multiplier': 'I',
}

HEADER_LEN = 372



FOOTER_FORMAT = {
    'reserved': 'I',
    }

FOOTER_LEN = 4


IMPORTANCE_FOOTER_FORMAT = {
    'voting_eligible_accounts_count': 'I',
    'harvesting_eligible_accounts_count': 'Q',
    'total_voting_balance': 'Q',
    'previous_importance_block_hash': '32s'
}

IMPORTANCE_FOOTER_LEN = 52


TX_H_FORMAT = {
    'size': 'I',
    'reserved_1': 'I',
    'signature': '64s',
    'signer_public_key': '32s',
    'reserved_2': 'I',
    'version': 'B',
    'network': 'B',
    'type': '2s',
    'max_fee': 'Q',
    'deadline': 'Q',
}

TX_H_LEN = 128


EMBED_TX_H_FORMAT = {
    'size': 'I',
    'reserved_1': 'I',
    'signer_public_key': '32s',
    'reserved_2': 'I',
    'version': 'B',
    'network': 'B',
    'type': '2s',
}

EMBED_TX_H_LEN = 48


SUBCACHE_MERKLE_ROOT_FORMAT = {
    'account_state': '32s',
    'namespace': '32s',
    'mosaic': '32s',
    'multisig': '32s',
    'hash_lock_info': '32s',
    'secret_lock_info': '32s',
    'account_restriction': '32s',
    'mosaic_restriction': '32s',
    'metadata': '32s'
}


def fmt_unpack(buffer,struct_format):
    """Helper function to unpack buffers based on static format spec"""
    return dict(
        zip(
            struct_format.keys(),
            struct.unpack('<'+''.join(struct_format.values()),buffer)
        )
    )


def public_key_to_address(public_key,network=104):
    """Converts a public key to an address."""
    part_one_hash_builder = hashlib.sha3_256()
    part_one_hash_builder.update(public_key)
    part_one_hash = part_one_hash_builder.digest()

    part_two_hash_builder = hashlib.new('ripemd160')
    part_two_hash_builder.update(part_one_hash)
    part_two_hash = part_two_hash_builder.digest()
    
    base = bytes([network]) + part_two_hash

    part_three_hash_builder = hashlib.sha3_256()
    part_three_hash_builder.update(base)
    checksum = part_three_hash_builder.digest()[0:3]
    
    address = base + checksum
    
    return base64.b32encode(address + bytes(0)).decode('utf8')[0:-1]


def deserialize_header(header):
    """Produce a python dict from a raw xym header blob"""

    header = fmt_unpack(header,HEADER_FORMAT)
    for k,v in HEADER_FORMAT.items():
        if k == 'type':
            header[k] = hexlify(header[k][::-1])
        elif k == 'beneficiary_address':
            header[k] = base64.b32encode(header[k]+bytes(0)).decode('utf8')[0:-1]
        elif v[-1] == 's':
            header[k] = hexlify(header[k])
    header['harvester'] = public_key_to_address(unhexlify(header['signer_public_key']))
    return header


def deserialize_footer(footer_data,header):
    """Produce a nested python dict from a raw xym footer blob"""

    # parse static footer fields
    i = 0
    if header['type'] == b'8043': #nemesis
        footer = fmt_unpack(footer_data[i:i+IMPORTANCE_FOOTER_LEN],IMPORTANCE_FOOTER_FORMAT)
        i += IMPORTANCE_FOOTER_LEN
    elif header['type'] == b'8143': #normal
        footer = fmt_unpack(footer_data[i:i+FOOTER_LEN],FOOTER_FORMAT)
        i += FOOTER_LEN
    elif header['type'] == b'8243': #importance
        footer = fmt_unpack(footer_data[i:i+IMPORTANCE_FOOTER_LEN],IMPORTANCE_FOOTER_FORMAT)
        i += IMPORTANCE_FOOTER_LEN
    else:
        raise ValueError(f"Unknown Block Type Encountered: {header['type']}")
        
    # parse transactions 
    tx_data = []
    tx_count = 0
    statement_count = 0
    total_fee = 0
    while i < len(footer_data):
        tx_header = fmt_unpack(footer_data[i:i+TX_H_LEN],TX_H_FORMAT)
        tx_header['id'] = statement_count + 1 #tx ids are 1-based
        tx_header['signature'] = hexlify(tx_header['signature'])
        tx_header['signer_public_key'] = hexlify(tx_header['signer_public_key'])
        tx_header['type'] = hexlify(tx_header['type'][::-1])
        tx_header['payload'] = deserialize_payload(footer_data[i+TX_H_LEN:i+tx_header['size']],tx_header['type'])
        tx_data.append(tx_header)
        
        total_fee += min(tx_header['max_fee'],tx_header['size'] * header['fee_multiplier'])
        tx_count += (1+tx_header['payload']['embedded_tx_count']) if 'embedded_tx_count' in tx_header['payload'] else 1 
        statement_count += 1
        i += tx_header['size'] + (8 - tx_header['size']) %8
        
    footer['total_fee'] = total_fee
    footer['statement_count'] = statement_count
    footer['tx_count'] = tx_count
    footer['transactions'] = tx_data

    return footer


def deserialize_payload(payload_data,payload_type):
    """Produce a nested python dict from a raw xym statemet payload"""

    i = 0

    #Account Link
    if payload_type == b'414c': #AccountKeyLinkTransaction
        schema = {
            'linked_public_key' : '32s',
            'link_action' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
        
    elif payload_type == b'424c': #NodeKeyLinkTransaction
        schema = {
            'linked_public_key' : '32s',
            'link_action' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    # Aggregate 	  	 
    elif payload_type == b'4141': #AggregateCompleteTransaction
        schema = {
            'transactions_hash' : '32s',
            'payload_size' : 'I',
            'aggregate_complete_transaction_reserved_1' : 'I'
        }
        i = 40
        payload = fmt_unpack(payload_data[:i],schema)
        e_tx_count = 0
        e_tx_data = []
        while i < 8 + payload['payload_size']:
            e_tx_header = fmt_unpack(payload_data[i:i+EMBED_TX_H_LEN],EMBED_TX_H_FORMAT)
            e_tx_header['id'] = e_tx_count + 1 #tx ids are 1-based
            e_tx_header['signer_public_key'] = hexlify(e_tx_header['signer_public_key'])
            e_tx_header['type'] = hexlify(e_tx_header['type'][::-1])
            e_tx_header['payload'] = deserialize_payload(payload_data[i+EMBED_TX_H_LEN:i+e_tx_header['size']],e_tx_header['type'])
            e_tx_data.append(e_tx_header)
            e_tx_count += 1 
            i += e_tx_header['size'] + (8 - e_tx_header['size']) %8

        payload['embedded_tx_count'] = e_tx_count
        payload['embedded_transactions'] = e_tx_data
        payload['cosignatures'] = payload_data[i:]          
    
    elif payload_type == b'4241': #AggregateBondedTransaction
        schema = {
            'transactions_hash' : '32s',
            'payload_size' : 'I',
            'aggregate_complete_transaction_reserved_1' : 'I'
        }
        i = 40
        payload = fmt_unpack(payload_data[:i],schema)
        e_tx_count = 0
        e_tx_data = []
        while i < 8 + payload['payload_size']:
            e_tx_header = fmt_unpack(payload_data[i:i+EMBED_TX_H_LEN],EMBED_TX_H_FORMAT)
            e_tx_header['id'] = e_tx_count + 1 #tx ids are 1-based
            e_tx_header['signer_public_key'] = hexlify(e_tx_header['signer_public_key'])
            e_tx_header['type'] = hexlify(e_tx_header['type'][::-1])
            e_tx_header['payload'] = deserialize_payload(payload_data[i+EMBED_TX_H_LEN:i+e_tx_header['size']],e_tx_header['type'])
            e_tx_data.append(e_tx_header)
            e_tx_count += 1 
            i += e_tx_header['size'] + (8 - e_tx_header['size']) %8

        payload['embedded_tx_count'] = e_tx_count
        payload['embedded_transactions'] = e_tx_data
        payload['cosignatures'] = payload_data[i:]          
    
    #Core 	  	 
    elif payload_type == b'4143': #VotingKeyLinkTransaction
        schema = {
            'linked_public_key' : '32s',
            'start_point' : 'I',
            'end_point' : 'I',
            'link_action' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    elif payload_type == b'4243': #VrfKeyLinkTransaction
        schema = {
            'linked_public_key' : '32s',
            'linked_action' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    #Mosaic 	  	 
    elif payload_type == b'414d': #MosaicDefinitionTransaction
        schema = {
            'id' : 'Q',
            'duration' : 'Q',
            'nonce' : 'I',
            'flags' : 'B',
            'divisibility' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    elif payload_type == b'424d': #MosaicSupplyChangeTransaction
        schema = {
            'mosaic_id' : 'Q',
            'delta' : 'Q',
            'action' : 'B',
        }
        payload = fmt_unpack(payload_data,schema)
    
    #Namespace 	  	 
    elif payload_type == b'414e': #NamespaceRegistrationTransaction
        schema = {
            'identifier' : 'Q',
            'id' : 'Q',
            'registration_type' : 'B',
            'name_size' : 'B',
        }
        payload = fmt_unpack(payload_data[:18],schema)
        payload['name'] = payload_data[18:]
        if payload['registration_type'] == 0:
            payload['duration'] = payload['identifier']
        elif payload['registration_type'] == 1:
            payload['parent_id'] = payload['identifier']
        else:
            raise ValueError(f'Unknown registration type for Namespace RegistrationTransaction: {payload["registration_type"]}')
        del payload['identifier']
    
    elif payload_type == b'424e': #AddressAliasTransaction
        schema = {
            'namespace_id' : 'Q',
            'address' : '24s',
            'alias_action' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    elif payload_type == b'434e': #MosaicAliasTransaction
        schema = {
            'namespace_id' : 'Q',
            'mosaid_id' : 'Q',
            'alias_action' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    #Metadata 	  	 
    elif payload_type == b'4144': #AccountMetadataTransaction
        schema = {
            'target_address' : '24s',
            'scoped_metadata_key' : 'Q',
            'value_size_delta': 'H',
            'value_size': 'H',
        }
        payload = fmt_unpack(payload_data[:36],schema)
        payload['value'] = payload_data[36:]
    
    elif payload_type == b'4244': #MosaicMetadataTransaction
        schema = {
            'target_address' : '24s',
            'scoped_metadata_key' : 'Q',
            'target_mosaic_id' : 'Q',
            'value_size_delta': 'H',
            'value_size': 'H',
        }
        payload = fmt_unpack(payload_data[:44],schema)
        payload['value'] = payload_data[44:]
    
    elif payload_type == b'4344': #NamespaceMetadataTransaction
        schema = {
            'target_address' : '24s',
            'scoped_metadata_key' : 'Q',
            'target_namespace_id' : 'Q',
            'value_size_delta': 'H',
            'value_size': 'H',
        }
        payload = fmt_unpack(payload_data[:44],schema)
        payload['value'] = payload_data[44:]
    
    #Multisignature 	  	 
    elif payload_type == b'4155': #MultisigAccountModificationTransaction
        schema = {
            'min_removal_delta' : 'B',
            'min_approval_delta' : 'b',
            'address_additions_count' : 'B',
            'address_deletions_count' : 'B',
            'multisig_account_modificaion_transacion_body_reserved_1' : 'I'
        }
        payload = fmt_unpack(payload_data[:8],schema)
        i = 8
        if payload['address_additions_count'] > 0:
            payload['address_additions'] = struct.unpack('<' + '24s'*payload['address_additions_count'], payload_data[i:i+payload['address_additions_count']*24])
            i += payload['address_additions_count']*24
        else: payload['address_additions'] = []

        if payload['address_deletions_count'] > 0:
            payload['address_deletions'] = struct.unpack('<' + '24s'*payload['address_deletions_count'], payload_data[i:i+payload['address_deletions_count']*24])
        else: payload['address_deletions'] = []
    
    #Hash Lock 	  	 
    elif payload_type == b'4148': #HashLockTransaction
        schema = {
            'reserved_1' : '8s', # NOT in the schema but shows up in the data ?!?
            'mosaic' : 'Q',
            'duration' : 'Q',
            'hash' : '32s'
        }
        payload = fmt_unpack(payload_data,schema)
    
    #Secret Lock 	  	 
    elif payload_type == b'4152': #SecretLockTransaction
        schema = {
            'recipient_address' : '24s',
            'secret' : '32s',
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'duration' : 'Q',
            'hash_algorithm' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    elif payload_type == b'4252': #SecretProofTransaction
        schema = {
            'recipient_address' : '24s',
            'secret' : '32s',
            'proof_size' : 'H',
            'hash_algorithm' : 'B',
        }
        payload = fmt_unpack(payload_data[:59],schema)
        payload['proof'] = payload_data[59:]
    
    #Account restriction 	  	 
    elif payload_type == b'4150': #AccountAddressRestrictionTransaction
        schema = {
            'restriction_type' : 'H',
            'restriction_additions_count' : 'B',
            'restriction_deletions_count' : 'B',
            'account_restriction_transaction_body_reserved_1' : 'I',
        }
        payload = fmt_unpack(payload_data[:8],schema)
        i = 8
        if payload['restriction_additions_count'] > 0:
            payload['restriction_additions'] = struct.unpack('<' + '24s'*payload['restriction_additions_count'], payload_data[i:i+payload['restriction_additions_count']*24])
            i += payload['restriction_additions_count']*24
        else: payload['restriction_additions'] = []
        
        if payload['restriction_deletions_count'] > 0:
            payload['restriction_deletions'] = struct.unpack('<' + '24s'*payload['restriction_deletions_count'], payload_data[i:i+payload['restriction_deletions_count']*24])
        else: payload['restriction_deletions'] = []
    
    elif payload_type == b'4250': #AccountMosaicRestrictionTransaction
        schema = {
            'restriction_type' : 'H',
            'restriction_additions_count' : 'B',
            'restriction_deletions_count' : 'B',
            'account_restriction_transaction_body_reserved_1' : 'I',
        }
        payload = fmt_unpack(payload_data[:8],schema)
        i = 8
        if payload['restriction_additions_count'] > 0:
            payload['restriction_additions'] = struct.unpack('<' + 'Q'*payload['restriction_additions_count'], payload_data[i:i+payload['restriction_additions_count']*8])
            i += payload['restriction_additions_count']*8
        else: payload['restriction_additions'] = []
        
        if payload['restriction_deletions_count'] > 0:
            payload['restriction_deletions'] = struct.unpack('<' + 'Q'*payload['restriction_deletions_count'], payload_data[i:i+payload['restriction_deletions_count']*8])
        else: payload['restriction_deletions'] = []
    
    elif payload_type == b'4350': #AccountOperationRestrictionTransaction
        schema = {
            'restriction_type' : 'H',
            'restriction_additions_count' : 'B',
            'restriction_deletions_count' : 'B',
            'account_restriction_transaction_body_reserved_1' : 'I',
        }
        payload = fmt_unpack(payload_data[:8],schema)
        i = 8
        if payload['restriction_additions_count'] > 0:
            payload['restriction_additions'] = struct.unpack('<' + '2s'*payload['restriction_additions_count'], payload_data[i:i+payload['restriction_additions_count']*2])
            i += payload['restriction_additions_count']*2
        else: payload['restriction_additions'] = []
        
        if payload['restriction_deletions_count'] > 0:
            payload['restriction_deletions'] = struct.unpack('<' + '2s'*payload['restriction_deletions_count'], payload_data[i:i+payload['restriction_deletions_count']*24])
        else: payload['restriction_deletions'] = []
    
    #Mosaic restriction 	  	 
    elif payload_type == b'4151': #MosaicGlobalRestrictionTransaction
        schema = {
            'mosaic_id' : 'Q',
            'reference_mosaic_id' : 'Q',
            'restriction_key' : 'Q',
            'previous_restriction_value' : 'Q',
            'new_restriction_value' : 'Q',
            'previous_restriction_type' : 'B',
            'new_restriction_type' : 'B'
        }
        payload = fmt_unpack(payload_data,schema)
    
    elif payload_type == b'4251': #MosaicAddressRestrictionTransaction
        schema = {
            'mosaic_id' : 'Q',
            'restriction_key' : 'Q',
            'previous_restriction_value' : 'Q',
            'new_restriction_value' : 'Q',
            'target_address' : '24s'
        }
        payload = fmt_unpack(payload_data,schema)
    
    #Transfer 	  	 
    elif payload_type == b'4154': #TransferTransaction
        schema = {
            'recipient_address' : '24s',
            'message_size' : 'H',
            'mosaics_count' : 'B',
            'transfer_transaction_body_reserved_1' : 'I',
            'transfer_transaction_body_reserved_2' : 'B',
        }
        payload = fmt_unpack(payload_data[:32],schema)
        i = 32
        if payload['mosaics_count'] > 0:
            payload['mosaics'] = struct.unpack('<' + 'Q'*payload['mosaics_count'], payload_data[i:i+payload['mosaics_count']*8])
            i += payload['mosaics_count']*8
        else: payload['mosaics'] = []
        payload['message'] = payload_data[i:]
    
    else:
        raise ValueError(f"Unknown Tx Payload Type Encountered: {payload_type}")

    return payload

def get_block_stats(block):
    """Extract basic summary data and flatten for tabular manipulation"""
    data = block['header'].copy()
    data['statement_count'] = block['footer']['statement_count']
    data['tx_count'] = block['footer']['tx_count']
    data['total_fee'] = block['footer']['total_fee']
    return data


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--block_dir", type=str, default='./data', help="Location of block store")
    parser.add_argument("--full_save_path", type=str, default='./block_data.pkl', help="path to write the extracted data to")
    parser.add_argument("--header_save_path", type=str, default='./block_header_df.pkl', help="path to write the extracted data to")
    parser.add_argument("--block_extension", type=str, default='.dat', help="extension of block files; must be unique")
    parser.add_argument("--db_offset_bytes", type=int, default=800, help="padding bytes between blocks")
    parser.add_argument("--save_tx_hashes", action='store_true', help="flag to keep full tx hashes")
    parser.add_argument("--save_subcache_merkle_roots", action='store_true', help="flag to keep subcache merkle roots")
    args = parser.parse_args()

    block_paths = glob.glob(os.path.join(args.block_dir,'**','*'+args.block_extension),recursive=True)
    block_format_pattern = re.compile('[0-9]{5}'+args.block_extension)
    block_paths = sorted(list(filter(lambda x: block_format_pattern.match(os.path.basename(x)),block_paths)))

    blocks = []
    for path in tqdm(block_paths):
        
        with open(path,mode='rb') as f:
            blk_data = f.read()
        
        i = args.db_offset_bytes

        while i < len(blk_data):

            # get fixed length data
            header = deserialize_header(blk_data[i:i+HEADER_LEN])
            footer = deserialize_footer(blk_data[i+HEADER_LEN:i+header['size']],header)
            i += header['size']
            block_hash, generation_hash = struct.unpack('<32s32s',blk_data[i:i+64])
            i += 64

            # get transaction hashes
            tx_hash_len = struct.unpack('I',blk_data[i:i+4])[0] * 2 * 32
            i += 4
            tx_hashes = None
            if args.save_tx_hashes:
                raise NotImplementedError('tx hash saving not implemented yet!')
            i += tx_hash_len

            # get sub cache merkle roots
            root_hash_len = struct.unpack('I',blk_data[i:i+4])[0] * 32
            i += 4
            merkle_roots = None
            if args.save_subcache_merkle_roots:
                merkle_roots = dict(zip(SUBCACHE_MERKLE_ROOT_FORMAT.keys(),struct.unpack('<'+''.join(SUBCACHE_MERKLE_ROOT_FORMAT.values()),blk_data[i:i+root_hash_len])))
            i += root_hash_len

            blocks.append({
                'header':header,
                'footer':footer,
                'block_hash':block_hash,
                'tx_hashes':tx_hashes,
                'subcache_merkle_roots':merkle_roots
            })

    print("data extraction complete!\n")

    with open(args.full_save_path, 'wb') as file:
        pickle.dump(blocks,file)

    print(f"full data written to {args.full_save_path}")

    header_df = pd.DataFrame.from_records([get_block_stats(x) for x in blocks])
    header_df['dateTime'] = pd.to_datetime(header_df['timestamp'],origin=pd.to_datetime('2021-03-16 00:06:25'),unit='ms')
    header_df = header_df.set_index('dateTime').sort_index(axis=0)
    header_df.to_pickle(args.header_save_path)

    print(f"header data written to {args.header_save_path}")
    print("exiting . . .")