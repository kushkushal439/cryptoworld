from Primitive_enums import Primitive
from collections import deque
import os


from CryptoPrimitives.base import CryptoPrimitive
from CryptoPrimitives.OWF import OWF
from CryptoPrimitives.PRG import PRG
from CryptoPrimitives.MAC import MAC
from CryptoPrimitives.PRF import PRF
from CryptoPrimitives.OWP import OWP
from CryptoPrimitives.PRP import PRP

# Import your pure logic functions from the Implementations folder
from Implementations.PA_1 import convert_owf_to_prg
from Implementations.PA_2 import ggm_prf_logic
from Implementations.PA_2 import convert_prg_to_prf, convert_prf_to_prg
from Implementations.PA_4 import CBC_Enc, CBC_Dec, OFB_Enc_Dec, CTR_Enc, CTR_Dec
from Implementations.PA_2 import luby_rackoff_forward, luby_rackoff_inverse


class God:
    def __init__(self):
        # Routing table: adjacency list of the Minicrypt Clique
        self.graph = {
            Primitive.OWF:  [Primitive.PRG, Primitive.OWP],
            Primitive.PRG:  [Primitive.OWF, Primitive.PRF],
            Primitive.PRF:  [Primitive.PRG, Primitive.PRP, Primitive.MAC, Primitive.OWP],
            Primitive.OWP:  [Primitive.OWF],
            Primitive.PRP:  [Primitive.PRF],
            Primitive.MAC:  [Primitive.PRF],
            Primitive.CRHF: [],
            Primitive.HMAC: []
        }

    def _find_shortest_path(self, start: Primitive, target: Primitive):
        if start == target:
            return [start]
            
        queue = deque([[start]])
        visited = {start}
        
        while queue:
            path = queue.popleft()
            node = path[-1]
            
            for neighbor in self.graph.get(node, []):
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
                    
        raise ValueError(f"No valid reduction path from {start.name} to {target.name}")


    def convert_owf_to_prg(self, owf_instance: OWF, **kwargs):
        """PA #1: HILL Construction"""
        return convert_owf_to_prg(owf_instance)

    def convert_prg_to_owf(self, prg_instance: PRG, **kwargs):
        """PA #1: HILL Construction (Backward Direction)"""
        # We can just use the PRG's generate function directly as the OWF evaluation
        return OWF(logic_func=lambda x: prg_instance.generate(seed=x, length=len(x)*8))

    #########################################################################
    
    def convert_owp_to_owf(self, owp_instance, **kwargs):
        """
        An OWP is a stronger primitive than an OWF, so we can just use the same instance.
        """
        return owp_instance
    

    def convert_owf_to_owp(self, owf_instance: OWF, **kwargs):
        """
        An OWF is a weaker primitive than an OWP, so we can just wrap the OWF's evaluation logic inside an OWP container.
        """
        return OWP(logic_func=owf_instance.evaluate)

    #########################################################################

    def convert_prg_to_prf(self, prg_instance: PRG, **kwargs):
        """PA #2: GGM Tree Construction"""
        return convert_prg_to_prf(prg_instance)

    def convert_prf_to_prg(self, prf_instance: PRF, **kwargs):
        """PA #2: Backward Direction"""
        return convert_prf_to_prg(prf_instance)

    #########################################################################

    # OWP PRG not needed, handled in cycle with OWF <-> OWP conversions

    #########################################################################

    def convert_prp_to_prf(self, prp_instance, **kwargs):
        """
        A PRP (like AES) is fundamentally a PRF (just reversible).
        We wrap it in a PRF container and pass both the key and query straight through.
        """
        def safe_eval(underlying_prp, k, q):
            # If the underlying PRP is our Luby-Rackoff construction,
            # it might not have a strictly enforced block size (or it expects strings of ANY EVEN length).
            # If it's AES, it strictly requires exactly 16 bytes block_size!
            bs = underlying_prp.block_size
            
            if bs is not None:
                # AES Mode (Fixed block size)
                if len(q) < bs:
                    q = q.ljust(bs, b'\x00')
                q = q[:bs]
            else:
                # Luby-Rackoff Mode (Variable but needs even length)
                if len(q) % 2 != 0:
                    q = q + b'\x00'
                    
            # Keys generally need the same treatment
            if bs is not None:
                k = k[:bs].ljust(bs, b'\x00')
                
            return underlying_prp.evaluate(key=k, query=q)
            
        return PRF(
            underlying_primitive=prp_instance,
            # PRF evaluate passes (underlying, key, query) to this lambda
            logic_func=safe_eval,
            block_size=prp_instance.block_size
        )

    def convert_prf_to_prp(self, prf_instance: PRF, **kwargs):
        """
        PA #3: Luby-Rackoff Construction (Feistel Network).
        Converts a PRF into a PRP using 4 rounds by default (Strong PRP).
        """
        
        # Default to 4 rounds for Strong PRP security
        rounds = kwargs.get("feistel_rounds", 4)
        
        # A Feistel network operates on two halves. 
        # If the PRF block size is B, the resulting PRP block size is 2B.
        prp_block_size = None
        if prf_instance.block_size is not None:
            prp_block_size = prf_instance.block_size * 2
            
        return PRP(
            underlying_primitive=prf_instance,
            forward_logic=lambda underlying, k, q: luby_rackoff_forward(underlying, k, q, rounds),
            inverse_logic=lambda underlying, k, q: luby_rackoff_inverse(underlying, k, q, rounds),
            block_size=prp_block_size
        )

    #########################################################################
        

    def convert_prf_to_mac(self, prf_instance, **kwargs):
        # Default to CBC if the user doesn't specify
        mode = kwargs.get("mac_mode", "CBC") 
        return MAC(prf_instance, mode=mode)
    
    def convert_mac_to_prf(self, mac_instance, **kwargs):
        """
        PA #5: MAC to PRF (Backward)
        Per the spec: A secure EUF-CMA MAC on uniformly random messages is a PRF.
        """
        return PRF(
            underlying_primitive=mac_instance,
            logic_func=lambda underlying_mac, k, q: underlying_mac.tag(key=k, message=q),
            # Safely fetch the block size using getattr to avoid the earlier bug
            block_size=getattr(mac_instance.underlying, 'block_size', None)
        )
    
    #########################################################################

    # No need to add PRP to MAC or MAC to PRP

    #########################################################################


    #########################################################################

    # no need to add owp to prf, (owp->owf->prg->prf).
    def convert_prf_to_owp(self, prf_instance, **kwargs):
        """
        Completing the Clique: PRF to OWP (Backward)
        Spec: PRF -> PRP (Luby-Rackoff); OWP f(k) = PRP_k(0^n).
        """
        
        # 1. Convert the PRF into a PRP using our existing Feistel network logic
        prp_instance = self.convert_prf_to_prp(prf_instance, **kwargs)

        block_size = prp_instance.block_size if prp_instance.block_size else 16
        zero_block = b'\x00' * block_size

        # The input 'x' to the OWP acts as the master key 'k' for the PRP!
        return OWP(
            logic_func=lambda x, **kw: prp_instance.evaluate(key=x, query=zero_block)
        )

    #########################################################################
        


    # --- The Orchestrators ---

    def convert(self, in_type: Primitive, out_type: Primitive, instance, **kwargs):
        """
        The internal dispatcher. Finds the specific 1-edge 
        method to call and passes along any extra configuration.
        """
        method_name = f"convert_{in_type.name.lower()}_to_{out_type.name.lower()}"
        method = getattr(self, method_name, None)
        
        if not method:
            raise NotImplementedError(f"No direct edge for {method_name}")
            
        # Pass the **kwargs into the specific conversion method!
        return method(instance, **kwargs)

    def reduce(self, in_type: Primitive, out_type: Primitive, instance, **kwargs):
        """
        Finds the shortest path and calls the dispatcher 
        repeatedly, forwarding configuration parameters.
        """
        path = self._find_shortest_path(in_type, out_type)
        
        curr_instance = instance
        for i in range(len(path) - 1):
            # Pass **kwargs through every step of the chain
            curr_instance = self.convert(path[i], path[i+1], curr_instance, **kwargs)
            
        return curr_instance

    def reduce_with_trace(self, in_type: Primitive, out_type: Primitive, instance, input_val, **kwargs):
        path = self._find_shortest_path(in_type, out_type)
        trace = []
        
        curr_instance = instance
        curr_val = input_val
        key_size = kwargs.get('key_size', 16)
        
        trace.append({"func": path[0].name, "val": curr_val.hex()[:32] + "..." if isinstance(curr_val, bytes) else str(curr_val)})

        for i in range(len(path) - 1):
            curr_instance = self.convert(path[i], path[i+1], curr_instance, **kwargs)
            
            try:
                if isinstance(curr_val, bytes) and len(curr_val) > key_size:
                    curr_val = curr_val[:key_size]

                if path[i+1] == Primitive.PRG:
                    # Pass the running value as the seed. Provide length as key_size * 8
                    curr_val = curr_instance.generate(seed=curr_val, length=key_size * 8)
                elif path[i+1] == Primitive.PRF:
                    # Use a static key so the output varies purely based on the user's input (query)
                    curr_val = curr_instance.evaluate(key=b'\x11'*key_size, query=curr_val)
                elif path[i+1] == Primitive.PRP:
                    if isinstance(curr_val, str):
                        curr_val = curr_val.encode('utf-8')
                        
                    # PRP (Luby-Rackoff or AES) strictly REQUIRES an even length query/16-byte block
                    # If this relies on AES block cipher directly, pad it to 16 bytes.
                    if len(curr_val) < key_size:
                        curr_val = curr_val.ljust(key_size, b'\x00')
                    # And enforce parity just in case
                    elif len(curr_val) % 2 != 0:
                        curr_val = curr_val + b'\x00'
                        
                    curr_val = curr_instance.evaluate(key=b'\x33'*key_size, query=curr_val)
                elif path[i+1] == Primitive.MAC:
                    if isinstance(curr_val, str):
                        curr_val = curr_val.encode('utf-8')
                    curr_val = curr_instance.tag(key=b'\x22'*key_size, message=curr_val)
                else:
                    curr_val = curr_instance.evaluate(curr_val)
            except Exception as e:
                curr_val = f"Error: {e}".encode()
                print(f"EXCEPTION at {path[i+1].name}: {e}")

            trace.append({
                "func": path[i+1].name, 
                "val": curr_val.hex() if isinstance(curr_val, bytes) else str(curr_val)
            })
                
        return curr_instance, trace
