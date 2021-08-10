"""NEM Extractor Script"""

import argparse
import base64
import glob
import hashlib
import numpy as np
import os
import pandas as pd
import pdb
import pickle
import re
import struct
import operator as op
import functools
from binascii import hexlify, unhexlify
from collections import defaultdict
from tqdm import tqdm

# describe the fixed structure of block entity bytes for unpacking

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
    'fee_multiplier': 'I'}

HEADER_LEN = 372

DB_OFFSET_BYTES = 800

FOOTER_FORMAT = {
    'reserved': 'I'}

FOOTER_LEN = 4


IMPORTANCE_FOOTER_FORMAT = {
    'voting_eligible_accounts_count': 'I',
    'harvesting_eligible_accounts_count': 'Q',
    'total_voting_balance': 'Q',
    'previous_importance_block_hash': '32s'}

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
    'deadline': 'Q',}

TX_H_LEN = 128


EMBED_TX_H_FORMAT = {
    'size': 'I',
    'reserved_1': 'I',
    'signer_public_key': '32s',
    'reserved_2': 'I',
    'version': 'B',
    'network': 'B',
    'type': '2s',}

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
    'metadata': '32s'}


TX_HASH_FORMAT = {
    'entity_hash': '32s',
    'merkle_component_hash': '32s'}

TX_HASH_LEN = 64


RECEIPT_SOURCE_FORMAT = {
    'primary_id': 'I',
    'secondary_id': 'I'
}

RECEIPT_SOURCE_LEN = 8


RECEIPT_FORMAT = {
    'size': 'I',
    'version': 'H',
    'type': 'H'}

RECEIPT_LEN = 8


ADDRESS_RESOLUTION_FORMAT = {
    'primary_id': 'I',
    'secondary_id': 'I',
    'resolved': '24s' }

ADDRESS_RESOLUTION_LEN = 24 + 8


MOSAIC_RESOLUTION_FORMAT = {
    'primary_id': 'I',
    'secondary_id': 'I',
    'resolved': 'Q' }

MOSAIC_RESOLUTION_LEN = 8 + 8


TX_NAME_MAP = {
    b'414c': 'Account Key Link',
    b'424c': 'Node Key Link',
    b'4141': 'Aggregate Complete',
    b'4241': 'Aggregate Bonded',
    b'4143': 'Voting Key Link',
    b'4243': 'Vrf Key Link',
    b'414d': 'Mosaic Definition',
    b'424d': 'Mosaic Supply Change',
    b'414e': 'Namespace Registration',
    b'424e': 'Address Alias',
    b'434e': 'Mosaic Alias',
    b'4144': 'Account Metadata',
    b'4244': 'Mosaic Metadata',
    b'4344': 'Namespace Metadata',
    b'4155': 'Multisig Account Modification',
    b'4148': 'Hash Lock',
    b'4152': 'Secret Lock',
    b'4252': 'Secret Proof',
    b'4150': 'Account Address Restriction',
    b'4250': 'Account Mosaic Restriction',
    b'4350': 'Account Operation Restriction',
    b'4151': 'Mosaic Global Restriction',
    b'4251': 'Mosaic Address Restriction',
    b'4154': 'Transfer'}



def fmt_unpack(buffer,struct_format):
    """Helper function to unpack buffers based on static format spec"""
    return dict(
        zip(
            struct_format.keys(),
            struct.unpack('<'+''.join(struct_format.values()),buffer)
        )
    )


def encode_address(address):
    """Encode address bytes into base32 with appropriate offset and pad"""
    return base64.b32encode(address + bytes(0)).decode('utf8')[0:-1]


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
    
    return encode_address(address)


def deserialize_header(header):
    """Produce a python dict from a raw xym header blob"""

    header = fmt_unpack(header,HEADER_FORMAT)
    for k,v in HEADER_FORMAT.items():
        if k == 'type':
            header[k] = hexlify(header[k][::-1])
        elif k == 'beneficiary_address':
            header[k] = encode_address(header[k])
        elif v[-1] == 's':
            header[k] = hexlify(header[k])
    header['harvester'] = public_key_to_address(unhexlify(header['signer_public_key']))
    return header


def deserialize_footer(footer_data,header):
    """Produce a nested python dict from a raw xym footer blob"""

    # parse static footer fields
    if header['type'] == b'8043': #nemesis
        footer = fmt_unpack(footer_data[:IMPORTANCE_FOOTER_LEN],IMPORTANCE_FOOTER_FORMAT)
        i = IMPORTANCE_FOOTER_LEN
    elif header['type'] == b'8143': #normal
        footer = fmt_unpack(footer_data[:FOOTER_LEN],FOOTER_FORMAT)
        i = FOOTER_LEN
    elif header['type'] == b'8243': #importance
        footer = fmt_unpack(footer_data[:IMPORTANCE_FOOTER_LEN],IMPORTANCE_FOOTER_FORMAT)
        i = IMPORTANCE_FOOTER_LEN
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
        tx_header['payload'] = deserialize_tx_payload(footer_data[i+TX_H_LEN:i+tx_header['size']],tx_header['type'])
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


def deserialize_tx_payload(payload_data,payload_type):
    """Produce a nested python dict from a raw xym statemet payload"""

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
            e_tx_header['payload'] = deserialize_tx_payload(payload_data[i+EMBED_TX_H_LEN:i+e_tx_header['size']],e_tx_header['type'])
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
            e_tx_header['payload'] = deserialize_tx_payload(payload_data[i+EMBED_TX_H_LEN:i+e_tx_header['size']],e_tx_header['type'])
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
            'link_action' : 'B'
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
        payload['target_address'] = encode_address(payload['target_address'])
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
        payload['target_address'] = encode_address(payload['target_address'])
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
        payload['target_address'] = encode_address(payload['target_address'])
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
        payload['recipient_address'] = encode_address(payload['recipient_address'])
    
    elif payload_type == b'4252': #SecretProofTransaction
        schema = {
            'recipient_address' : '24s',
            'secret' : '32s',
            'proof_size' : 'H',
            'hash_algorithm' : 'B',
        }
        payload = fmt_unpack(payload_data[:59],schema)
        payload['recipient_address'] = encode_address(payload['recipient_address'])
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
        payload['target_address'] = encode_address(payload['target_address'])
    
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
        payload['mosaics'] = []
        for _ in range(payload['mosaics_count']):
            mosaic = {}
            mosaic['mosaic_id'] = struct.unpack('<Q',payload_data[i:i+8])[0]
            mosaic['amount'] = struct.unpack('<Q',payload_data[i+8:i+16])[0]
            payload['mosaics'].append(mosaic)
            i += 16
        payload['message'] = payload_data[-payload['message_size']:]
        payload['recipient_address'] = encode_address(payload['recipient_address'])
    
    else:
        raise ValueError(f"Unknown Tx payload type encountered: {payload_type}")

    return payload


def deserialize_receipt_payload(payload_data,receipt_type):
    """Produce a nested python dict from a raw receipt payload"""
    
    if receipt_type == 0x0000: # reserved receipt
        payload = None

    elif receipt_type == 0x124D: # mosaic rental fee receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'sender_address' : '24s',
            'recipient_address' : '24s'
        }
        payload = fmt_unpack(payload_data,schema)
        payload['sender_address'] = encode_address(payload['sender_address'])
        payload['recipient_address'] = encode_address(payload['recipient_address'])

    elif receipt_type == 0x134E: # namespace rental fee receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'sender_address' : '24s',
            'recipient_address' : '24s'
        }
        payload = fmt_unpack(payload_data,schema)
        payload['sender_address'] = encode_address(payload['sender_address'])
        payload['recipient_address'] = encode_address(payload['recipient_address'])

    elif receipt_type == 0x2143: # harvest fee receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x2248: # lock hash completed receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x2348: # lock hash expired receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x2252: # lock secret completed receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x2352: # lock secret expired receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x3148: # lock hash created receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x3152: # lock secret created receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
            'target_address' : '24s',
        }
        payload = fmt_unpack(payload_data,schema)
        payload['target_address'] = encode_address(payload['target_address'])

    elif receipt_type == 0x414D: # mosaic expired receipt
        schema = {
            'mosaic_id' : 'Q'
        }
        payload = fmt_unpack(payload_data,schema)

    elif receipt_type == 0x414E: # namespace expired receipt
        schema = {
            'mosaic_id' : 'Q'
        }
        payload = fmt_unpack(payload_data,schema)

    elif receipt_type == 0x424E: # namespace deleted receipt
        schema = {
            'mosaic_id' : 'Q'
        }
        payload = fmt_unpack(payload_data,schema)

    elif receipt_type == 0x5143: # inflation receipt
        schema = {
            'mosaic_id' : 'Q',
            'amount' : 'Q',
        }
        payload = fmt_unpack(payload_data,schema)

    elif receipt_type == 0xE143: # transaction group receipt
        receipt_source = fmt_unpack(payload_data[:RECEIPT_SOURCE_LEN], RECEIPT_SOURCE_FORMAT)
        i = RECEIPT_SOURCE_LEN

        receipt_count = struct.unpack("<I", payload_data[i:i+4])[0]
        i += 4

        payload = {'receipt_source': receipt_source, 'receipts': [] }
        for k in range(receipt_count):
            receipt = fmt_unpack(payload_data[i:i + RECEIPT_LEN], RECEIPT_FORMAT)
            receipt['payload'] = deserialize_receipt_payload(payload_data[i + RECEIPT_LEN:i + receipt['size']],receipt['type'])
            i += receipt['size']

            payload['receipts'].append(receipt)

    else:
        raise ValueError(f"Unknown receipt payload type encountered: {hex(receipt_type)}")

    return payload


def deserialize_transaction_statements(stmt_data, i):
    count = struct.unpack("<I", stmt_data[i:i+4])
    i += 4

    statements = []
    for j in range(count[0]):
        receipt_source = fmt_unpack(stmt_data[i:i + RECEIPT_SOURCE_LEN], RECEIPT_SOURCE_FORMAT)
        i += RECEIPT_SOURCE_LEN

        receipt_count = struct.unpack("<I", stmt_data[i:i+4])[0]
        i += 4

        statement = { 'receipt_source': receipt_source, 'receipts': [] }
        for k in range(receipt_count):
            receipt = fmt_unpack(stmt_data[i:i + RECEIPT_LEN], RECEIPT_FORMAT)
            receipt['payload'] = deserialize_receipt_payload(stmt_data[i + RECEIPT_LEN:i + receipt['size']],receipt['type'])
            i += receipt['size']

            statement['receipts'].append(receipt)

        statements.append(statement)

    return i, statements


def deserialize_address_resolution_statements(stmt_data, i):
    count = struct.unpack("<I", stmt_data[i:i+4])
    i += 4

    statements = []
    for j in range(count[0]):
        key = struct.unpack('24s', stmt_data[i:i+24])[0]
        i += 24

        resolution_count = struct.unpack("<I", stmt_data[i:i+4])[0]
        i += 4

        statement = { 'key': key, 'resolutions': [] }
        for k in range(resolution_count):
            address_resolution = fmt_unpack(stmt_data[i:i + ADDRESS_RESOLUTION_LEN], ADDRESS_RESOLUTION_FORMAT)
            i += ADDRESS_RESOLUTION_LEN
            statement['resolutions'].append(address_resolution)

        statements.append(statement)

    return i, statements


def deserialize_mosaic_resolution_statements(stmt_data, i):
    count = struct.unpack("<I", stmt_data[i:i+4])
    i += 4

    statements = []
    for j in range(count[0]):
        key = struct.unpack('<Q', stmt_data[i:i+8])[0]
        i += 8

        resolution_count = struct.unpack("<I", stmt_data[i:i+4])[0]
        i += 4

        statement = { 'key': key, 'resolutions': [] }
        for k in range(resolution_count):
            mosaic_resolution = fmt_unpack(stmt_data[i:i + MOSAIC_RESOLUTION_LEN], MOSAIC_RESOLUTION_FORMAT)
            i += MOSAIC_RESOLUTION_LEN
            statement['resolutions'].append(mosaic_resolution)

        statements.append(statement)

    return i, statements


def state_map_tx(tx,height,fee_multiplier,state_map):
    """take a transaction, height, fee multiplier, and update a given state map with resulting state changes"""

    # TODO: handle flows for *all* mosaics, not just XYM
    address = public_key_to_address(unhexlify(tx['signer_public_key']))
    
    # transfer tx
    if tx['type'] == b'4154':
        if len(tx['payload']['message']) and tx['payload']['message'][0] == 0xfe:
            state_map[address]['delegation_requests'][tx['payload']['recipient_address']].append(height)
        elif tx['payload']['mosaics_count'] > 0:
            for mosaic in tx['payload']['mosaics']:
                if hex(mosaic['mosaic_id']) in ['0x6bed913fa20223f8','0xe74b99ba41f4afee']: # only care about XYM for now, hardcoded alias
                    state_map[address]['xym_balance'][height] -= mosaic['amount']
                    state_map[tx['payload']['recipient_address']]['xym_balance'][height] += mosaic['amount']
    
    # key link tx          
    elif tx['type'] in [b'4243',b'424c',b'414c']:
        if tx['type'] == b'4243': 
            link_key = 'vrf_key_link'
        elif tx['type'] == b'424c': 
            link_key = 'node_key_link'
        elif tx['type'] == b'414c': 
            link_key = 'account_key_link'
        if tx['payload']['link_action'] == 1:
            state_map[address][link_key][public_key_to_address(tx['payload']['linked_public_key'])].append([height,np.inf])
        else:
            state_map[address][link_key][public_key_to_address(tx['payload']['linked_public_key'])][-1][1] = height
    
    # aggregate tx
    elif tx['type'] in [b'4141',b'4241']:
        for sub_tx in tx['payload']['embedded_transactions']:
            state_map_tx(sub_tx,height,None,state_map)
    
    # handle fees
    if fee_multiplier is not None:
        state_map[address]['xym_balance'][height] -= min(tx['max_fee'],tx['size']*fee_multiplier)
    
    
def state_map_rx(rx,height,state_map):
    """take a receipt and height, and update a given state map with resulting state changes"""
    
    # rental fee receipts
    if rx['type'] in [0x124D, 0x134E]: 
        if hex(rx['payload']['mosaic_id']) in ['0x6bed913fa20223f8','0xe74b99ba41f4afee']:
            state_map[rx['payload']['sender_address']]['xym_balance'][height] -= rx['payload']['amount']
            state_map[rx['payload']['recipient_address']]['xym_balance'][height] += rx['payload']['amount']
            
    # balance change receipts (credit)
    elif rx['type'] in [0x2143,0x2248,0x2348,0x2252,0x2352]:
        state_map[rx['payload']['target_address']]['xym_balance'][height] += rx['payload']['amount']
        
    # balance change receipts (debit)
    elif rx['type'] == [0x3148,0x3152]:
        state_map[rx['payload']['target_address']]['xym_balance'][height] -= rx['payload']['amount']
    
    # aggregate receipts
    if rx['type'] == 0xE143:
        for sub_rx in rx['receipts']:
            state_map_rx(sub_rx,height,state_map)


def get_block_stats(block):
    """Extract basic summary data from a block, and flatten for tabular manipulation"""
    data = block['header'].copy()
    data['statement_count'] = block['footer']['statement_count']
    data['tx_count'] = block['footer']['tx_count']
    data['total_fee'] = block['footer']['total_fee']
    return data


def statement_paths(statement_extension='.stmt', block_dir='./data'):    
    statement_paths = glob.glob(os.path.join(block_dir,'**','*'+statement_extension),recursive=True)
    statement_format_pattern = re.compile('[0-9]{5}'+statement_extension)
    statement_paths = sorted(list(filter(lambda x: statement_format_pattern.match(os.path.basename(x)),statement_paths)))
    return statement_paths


def statements(statement_paths, db_offset_bytes=DB_OFFSET_BYTES):
    stmt_height = 0
    statement_paths_ = tqdm(statement_paths)
    for path in statement_paths_:
        statements = {
            'transaction_statements':{},
            'address_resolution_statements': {},
            'mosaic_resolution_statements': {}
            }

        statement_paths_.set_description(f"processing statement file: {path}")

        with open(path,mode='rb') as f:
            stmt_data = f.read()
        
        i = db_offset_bytes

        while i < len(stmt_data):
            # TODO: statement deserialization can probably be inlined efficiently or at least aggregated into one function
            i, transaction_statements = deserialize_transaction_statements(stmt_data, i)
            i, address_resolution_statements = deserialize_address_resolution_statements(stmt_data, i)
            i, mosaic_resolution_statements = deserialize_mosaic_resolution_statements(stmt_data, i)

            stmt_height += 1
            statements['transaction_statements'] = transaction_statements
            statements['address_resolution_statements'] = address_resolution_statements
            statements['mosaic_resolution_statements'] = mosaic_resolution_statements
            yield stmt_height, statements, path


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--block_dir", type=str, default='./data', help="Location of block store")
    parser.add_argument("--block_save_path", type=str, default='./block_data.pkl', help="path to write the extracted block data to")
    parser.add_argument("--statement_save_path", type=str, default='./stmt_data.pkl', help="path to write the extracted statement data to")
    parser.add_argument("--state_save_path", type=str, default='./state_map.pkl', help="path to write the extracted statement data to")
    parser.add_argument("--header_save_path", type=str, default='./block_header_df.pkl', help="path to write the extracted data to")
    parser.add_argument("--block_extension", type=str, default='.dat', help="extension of block files; must be unique")
    parser.add_argument("--statement_extension", type=str, default='.stmt', help="extension of block files; must be unique")
    parser.add_argument("--db_offset_bytes", type=int, default=DB_OFFSET_BYTES, help="padding bytes at start of storage files")
    parser.add_argument("--save_tx_hashes", action='store_true', help="flag to keep full tx hashes")
    parser.add_argument("--save_subcache_merkle_roots", action='store_true', help="flag to keep subcache merkle roots")
    parser.add_argument("--quiet", action='store_true', help="do not show progress bars")
    
    args = parser.parse_args()

    if args.quiet:
        tqdm = functools.partial(tqdm, disable=True)
    
    block_paths = glob.glob(os.path.join(args.block_dir,'**','*'+args.block_extension),recursive=True)
    block_format_pattern = re.compile('[0-9]{5}'+args.block_extension)
    block_paths = tqdm(sorted(list(filter(lambda x: block_format_pattern.match(os.path.basename(x)),block_paths))))

    blocks = []
    for path in block_paths:
        
        block_paths.set_description(f"processing block file: {path}")

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
            num_tx_hashes = struct.unpack('I',blk_data[i:i+4])[0]
            i += 4
            tx_hashes = None
            if args.save_tx_hashes:
                tx_hashes = []
                for _ in range(num_tx_hashes):
                    tx_hashes.append(fmt_unpack(blk_data[i:i+TX_HASH_LEN],TX_HASH_FORMAT))
                    i += TX_HASH_LEN
            else:    
                i += num_tx_hashes * TX_HASH_LEN

            # get sub cache merkle roots
            root_hash_len = struct.unpack('I',blk_data[i:i+4])[0] * 32
            i += 4
            merkle_roots = None
            if args.save_subcache_merkle_roots:
                merkle_roots = fmt_unpack(blk_data[i:i+root_hash_len],SUBCACHE_MERKLE_ROOT_FORMAT) 
            i += root_hash_len

            blocks.append({
                'header':header,
                'footer':footer,
                'block_hash':block_hash,
                'tx_hashes':tx_hashes,
                'subcache_merkle_roots':merkle_roots
            })

    state_map = defaultdict(lambda:{
        'xym_balance': defaultdict(lambda:0),
        'delegation_requests': defaultdict(lambda:[]),
        'vrf_key_link': defaultdict(lambda:[]),
        'node_key_link': defaultdict(lambda:[]),
        'account_key_link': defaultdict(lambda:[])
    })

    statements_ = statements(statement_paths(block_dir=args.block_dir, statement_extension=args.statement_extension))
    blocks_ = tqdm(sorted(blocks, key=lambda b:b['header']['height']))
    s_height, stmts, s_path = next(statements_)
    for block in blocks_:
        height = block['header']['height']
        blocks_.set_description(f"processing block: {height}")
        for tx in block['footer']['transactions']:
            state_map_tx(tx,height,block['header']['fee_multiplier'],state_map)

        if s_height > height:
            continue

        while s_height < height:
            s_height, stmts, s_path = next(statements_)

        for stmt in stmts['transaction_statements']:
            for rx in stmt['receipts']:
                state_map_rx(rx,height,state_map)

    assert len([*statements_]) == 0

    print("block data extraction complete!\n")
    print("statement data extraction complete!\n")

    print("state mapping complete!\n")
    
    with open(args.block_save_path, 'wb') as file:
        pickle.dump(blocks,file)

    print(f"block data written to {args.block_save_path}")

    header_df = pd.DataFrame.from_records([get_block_stats(x) for x in blocks])
    header_df['dateTime'] = pd.to_datetime(header_df['timestamp'],origin=pd.to_datetime('2021-03-16 00:06:25'),unit='ms')
    header_df = header_df.set_index('dateTime').sort_index(axis=0)
    header_df.to_pickle(args.header_save_path)

    print(f"header data written to {args.header_save_path}")

    # with open(args.statement_save_path, 'wb') as file:
    #     pickle.dump(statements,file)

    print(f"statement data written to {args.statement_save_path}")


    # TODO: fix state serialization; need to convert from defaultdict to regular dictionaries first
    # with open(args.state_save_path, 'wb') as file:
    #     pickle.dump(state_map,file)

    # print(f"state data written to {args.statement_save_path}")

    print("exiting . . .")
