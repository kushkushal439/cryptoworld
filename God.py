from Primitive_enums import Primitive
from collections import deque
import os


from CryptoPrimitives.base import CryptoPrimitive
from CryptoPrimitives.OWF import OWF
from CryptoPrimitives.PRG import PRG
from CryptoPrimitives.MAC import MAC
from CryptoPrimitives.PRF import PRF

# Import your pure logic functions from the Implementations folder
from Implementations.PA_1 import convert_owf_to_prg
from Implementations.PA_2 import ggm_prf_logic
from Implementations.PA_2 import convert_prg_to_prf, convert_prf_to_prg
from Implementations.PA_4 import CBC_Enc, CBC_Dec, OFB_Enc_Dec, CTR_Enc, CTR_Dec


class God:
    def __init__(self):
        # Routing table: adjacency list of the Minicrypt Clique
        self.graph = {
            Primitive.OWF:  [Primitive.PRG, Primitive.OWP],
            Primitive.PRG:  [Primitive.PRF, Primitive.OWF],
            Primitive.PRF:  [Primitive.PRP, Primitive.MAC, Primitive.PRG],
            Primitive.OWP:  [Primitive.PRG, Primitive.PRF],
            Primitive.PRP:  [Primitive.PRF, Primitive.MAC],
            Primitive.CRHF: [Primitive.HMAC],
            Primitive.HMAC: [Primitive.MAC, Primitive.CRHF],
            Primitive.MAC:  [Primitive.PRF, Primitive.CRHF]
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


    # --- Specific Edge Conversions (The "Constructor" instances) ---
    def convert_owp_to_prg(self, owp_instance, **kwargs):
        """
        PA #1: An OWP is mathematically a OWF, so we use the exact same HILL/GL construction.
        """
        # Just route it directly to the OWF->PRG logic you already wrote!
        return self.convert_owf_to_prg(owp_instance, **kwargs)

    def convert_prp_to_prf(self, prp_instance, **kwargs):
        """
        A PRP (like AES) is fundamentally a PRF (just reversible).
        We can just pass the instance straight through.
        """
        return prp_instance

    def convert_owf_to_prg(self, owf_instance: OWF, **kwargs):
        """PA #1: HILL Construction"""
        return convert_owf_to_prg(owf_instance)

    def convert_prg_to_prf(self, prg_instance: PRG, **kwargs):
        """PA #2: GGM Tree Construction"""
        return convert_prg_to_prf(prg_instance)

    def convert_prf_to_prg(self, prf_instance: PRF, **kwargs):
        """PA #2: Backward Direction"""
        return convert_prf_to_prg(prf_instance)
        

    def convert_prf_to_mac(self, prf_instance, **kwargs):
        """PA #5: PRF to MAC"""
        # Default to CBC if the user doesn't specify
        mode = kwargs.get("mac_mode", "CBC") 
        return MAC(prf_instance, mode=mode)
        


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
                if path[i+1] == Primitive.PRG:
                    # Pass the running value as the seed
                    curr_val = curr_instance.generate(seed=curr_val, length=16)
                elif path[i+1] == Primitive.PRF:
                    # Use a static key so the output varies purely based on the user's input (query)
                    curr_val = curr_instance.evaluate(key=b'\x11'*key_size, query=curr_val)
                elif path[i+1] == Primitive.MAC:
                    curr_val = curr_instance.tag(key=b'\x22'*key_size, message=curr_val)
                else:
                    curr_val = curr_instance.evaluate(curr_val)
            except Exception as e:
                curr_val = f"Error: {e}".encode()

            trace.append({
                "func": path[i+1].name, 
                "val": curr_val.hex()[:32] + "..." if isinstance(curr_val, bytes) else str(curr_val)
            })
                
        return curr_instance, trace
                
        return curr_instance, trace
  