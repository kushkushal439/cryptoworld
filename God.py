from Primitive_enums import Primitive
from CryptoPrimitives.base import CryptoPrimitive
from CryptoPrimitives.OWF import OWF
from CryptoPrimitives.PRG import PRG
from collections import deque

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

    def convert_owf_to_prg(self, owf_instance: OWF):
        """PA #1: HILL Construction"""
        def hill_logic_func(seed, length):
            # 1. Use the injected owf_instance.evaluate() to run the HILL math
            # 2. Extract hard-core bits
            # 3. Return the pseudo-random stream
            pass
            
        # Return a new PRG container holding the HILL logic
        return PRG(hill_logic_func)

    def convert_prg_to_prf(self, prg_instance: PRG):
        """PA #2: GGM Tree Construction"""
        return GGM_PRF(prg_instance)

    def convert_prf_to_mac(self, prf_instance: PRF):
        """PA #5: Fixed-length PRF-MAC"""
        return PRF_MAC(prf_instance)


    # --- The Orchestrators ---

    def convert(self, in_type: Primitive, out_type: Primitive, instance):
        """
        The internal dispatcher. Finds the specific 1-edge 
        method to call. 
        """
        method_name = f"convert_{in_type.name.lower()}_to_{out_type.name.lower()}"
        method = getattr(self, method_name, None)
        
        if not method:
            raise NotImplementedError(f"No direct edge for {method_name}")
            
        return method(instance)

    def reduce(self, in_type: Primitive, out_type: Primitive, instance):
        """
        Finds the shortest path and calls the dispatcher 
        repeatedly. 
        """
        path = self._find_shortest_path(in_type, out_type)
        
        curr_instance = instance
        for i in range(len(path) - 1):
            curr_instance = self.convert(path[i], path[i+1], curr_instance)
            
        return curr_instance