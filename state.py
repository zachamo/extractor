
import msgpack
import numpy as np
import networkx as nx
from binascii import unhexlify
from collections import defaultdict

from util import public_key_to_address

class XYMStateMap():
    """Efficient, mutable representation of XYM network state

    Parameters
    ----------
    state_map: dict, optional
        Pre-existing state map to initialize internal state

    Attributes
    ----------
    state_map: defaultdict
        Dict mapping addresses to recorded quantities
    tracked_mosaics: list[str]
        List of string aliases for mosaic(s) to track the balance of

    """

    def __init__(self,state_map={}):
        
        if len(state_map):
            state_map = {k:{
                'xym_balance': defaultdict(lambda:0,v['xym_balance']),
                'delegation_requests': defaultdict(list,v['delegation_requests']),
                'vrf_key_link': defaultdict(list,v['vrf_key_link']),
                'node_key_link': defaultdict(list,v['node_key_link']),
                'account_key_link': defaultdict(list,v['account_key_link']),
                'harvested':defaultdict(list,v['harvested']),
                'delegated':defaultdict(list,v['delegated'])
            } for k,v in state_map.items()}

        self.state_map = defaultdict(lambda:{
                'xym_balance': defaultdict(lambda:0),
                'delegation_requests': defaultdict(list),
                'vrf_key_link': defaultdict(list),
                'node_key_link': defaultdict(list),
                'account_key_link': defaultdict(list),
                'harvested':defaultdict(list),
                'delegated':defaultdict(list)
            }, state_map)

        self.tracked_mosaics = ['0x6bed913fa20223f8','0xe74b99ba41f4afee'] # only care about XYM for now, hardcoded alias
        self.node_color = 'CornflowerBlue'
        self.delegate_color = 'LightBlue'


    def __getitem__(self,addr):
        return self.state_map[addr]


    @classmethod
    def read_msgpack(cls,msgpack_path):
        """Read data from a mesgpack binary blob and build a state map"""
        if type(msgpack_path) == str:
            with open(msgpack_path,'rb') as f:
                state_map = msgpack.unpack(f,unicode_errors=None,raw=False)
        else:
            raise TypeError(f"Unrecognized type {type(msgpack_path)} for read_msgpack, path str")

        return cls(state_map=state_map)


    def keys(self):
        """Produce a view of all addresses in the state map"""
        return self.state_map.keys()


    def values(self):
        """Produce a view of all address data in the state map"""
        return self.state_map.values()


    def insert_tx(self,tx,height,fee_multiplier):
        """Insert a transaction into the state map and record resulting changes
        
        Parameters
        ----------
        tx: dict
            Deserialized transaction
        height: int
            Height of transaction
        fee_multiplier: float
            Fee multiplier for transaction's containing block

        """

        # TODO: handle flows for *all* mosaics, not just XYM
        address = public_key_to_address(unhexlify(tx['signer_public_key']))
        
        if tx['type'] == b'4154': # transfer tx
            if len(tx['payload']['message']) and tx['payload']['message'][0] == 0xfe:
                self.state_map[address]['delegation_requests'][tx['payload']['recipient_address']].append(height)
            elif tx['payload']['mosaics_count'] > 0:
                for mosaic in tx['payload']['mosaics']:
                    if hex(mosaic['mosaic_id']) in self.tracked_mosaics:
                        self.state_map[address]['xym_balance'][height] -= mosaic['amount']
                        self.state_map[tx['payload']['recipient_address']]['xym_balance'][height] += mosaic['amount']
        
        elif tx['type'] in [b'4243',b'424c',b'414c']: # key link tx          
            if tx['type'] == b'4243': 
                link_key = 'vrf_key_link'
            elif tx['type'] == b'424c': 
                link_key = 'node_key_link'
            elif tx['type'] == b'414c': 
                link_key = 'account_key_link'
            if tx['payload']['link_action'] == 1:
                self.state_map[address][link_key][public_key_to_address(tx['payload']['linked_public_key'])].append([height,np.inf])
            else:
                self.state_map[address][link_key][public_key_to_address(tx['payload']['linked_public_key'])][-1][1] = height
        
        elif tx['type'] in [b'4141',b'4241']: # aggregate tx
            for sub_tx in tx['payload']['embedded_transactions']:
                self.insert_tx(sub_tx,height,None)
        
        if fee_multiplier is not None: # handle fees
            self.state_map[address]['xym_balance'][height] -= min(tx['max_fee'],tx['size']*fee_multiplier)


    def insert_block(self,block):
        """Insert a block into the state map and record resulting changes
        
        Parameters
        ----------
        block: dict
            Deserialized block

        """
        header = block['header']
        height = header['height']

        # handle harvester information
        self.state_map[header['beneficiary_address']]['harvested'][height] = header['harvester']
        if header['harvester'] != header['beneficiary_address']:
            self.state_map[header['harvester']]['delegated'][height] = header['beneficiary_address']

        # handle transactions
        for tx in block['footer']['transactions']:
            self.insert_tx(tx,height,header['fee_multiplier'])


    def insert_rx(self,rx,height):
        """Insert a receipt into the state map and record resulting changes
        
        Parameters
        ----------
        rx: dict
            Deserialized receipt
        height: int
            Height of receipt

        """
    
        if rx['type'] in [0x124D, 0x134E]: # rental fee receipts
            if hex(rx['payload']['mosaic_id']) in ['0x6bed913fa20223f8','0xe74b99ba41f4afee']:
                self.state_map[rx['payload']['sender_address']]['xym_balance'][height] -= rx['payload']['amount']
                self.state_map[rx['payload']['recipient_address']]['xym_balance'][height] += rx['payload']['amount']
                
        elif rx['type'] in [0x2143,0x2248,0x2348,0x2252,0x2352]: # balance change receipts (credit)
            self.state_map[rx['payload']['target_address']]['xym_balance'][height] += rx['payload']['amount']
            
        elif rx['type'] == [0x3148,0x3152]: # balance change receipts (debit)
            self.state_map[rx['payload']['target_address']]['xym_balance'][height] -= rx['payload']['amount']
        
        if rx['type'] == 0xE143: # aggregate receipts
            for sub_rx in rx['receipts']:
                self.insert_rx(sub_rx,height)


    def to_dict(self):
        """Convert internal state map to serializable dictionary"""
        sm_dict = dict(self.state_map)
        for k, v in sm_dict.items():
            sm_dict[k] = dict(v)
            for kk, vv in v.items():
                sm_dict[k][kk] = dict(vv)
        return sm_dict


    def to_msgpack(self,msgpack_path):
        """Produce serialized blob with msgpack"""
        with open(msgpack_path, 'wb') as f:
            f.write(msgpack.packb(self.to_dict()))


    def get_harvester_graph(self,min_height=0,max_height=np.inf,min_node_size=1,min_delegate_size=1):
        """Produce a graph representing harvester-node relationships for a range of network heights
           
        Parameters
        ----------
        min_height: int
            Height at which to begin recording harvesting signatures
        max_height: int
            Height 
        min_node_size: int, optional
        min_delegate_size: int, optional
            
        """
        node_map = defaultdict(lambda:[])
        
        for k,v in self.state_map.items():
            for height, addr in v['harvested'].items():
                if min_height <= height <= max_height:
                    node_map[k].append(addr)

        delegate_map = defaultdict(lambda:[])
    
        for k,v in self.state_map.items():
            for height, addr in v['delegated'].items():
                if min_height <= height <= max_height:
                    delegate_map[k].append(addr)
        
        node_size_map = {k:{'size':len(v),'color':self.node_color} for k,v in node_map.items() if len(v) >= min_node_size}
        delegate_size_map = {k:{'size':len(v),'color':self.delegate_color} for k,v in delegate_map.items() if len(v) >= min_delegate_size}

        graph = nx.DiGraph()
        graph.add_nodes_from(node_size_map.items())
        graph.add_nodes_from(delegate_size_map.items())
        
        for node,delegates in node_map.items():
            if node in node_size_map:
                d_map = defaultdict(lambda:0)
                for d in delegates:
                    if d in delegate_size_map:
                        d_map[d] += 1
                graph.add_edges_from([(node,d,{'weight':d_map[d]}) for d in d_map])
        
        nx.set_node_attributes(graph,node_size_map)
        
        return graph


    def get_harvester_bubbles(self,min_height=0,max_height=np.inf,min_node_size=1,min_delegate_size=1):
        """Produce a bubble chart representing harvester-node relationships for a range of network heights
           
        Parameters
        ----------
        min_height: int
            Height at which to begin recording harvesting signatures
        max_height: int
            Height 
        min_node_size: int, optional
        min_delegate_size: int, optional
            
        """
        node_map = defaultdict(lambda:[])
        
        for k,v in self.state_map.items():
            for height, addr in v['harvested'].items():
                if min_height <= height <= max_height:
                    node_map[k].append(addr)

        delegate_map = defaultdict(lambda:[])
    
        for k,v in self.state_map.items():
            for height, addr in v['delegated'].items():
                if min_height <= height <= max_height:
                    delegate_map[k].append(addr)
        
        node_size_map = {k:{'size':len(v),'color':self.node_color, 'type': 'node'} for k,v in node_map.items() if len(v) >= min_node_size}
        delegate_size_map = {k:{'size':len(v),'color':self.delegate_color, 'parent': max(set(v), key = v.count), 'type': 'delegate'} for k,v in delegate_map.items() if len(v) >= min_delegate_size}

        graph = nx.Graph()
        graph.add_nodes_from(node_size_map.items())
        graph.add_nodes_from(delegate_size_map.items())
        
        return graph


if __name__ == "__main__":
    pass