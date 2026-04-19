from Primitive_enums import Primitive
from CryptoPrimitives.base import CryptoPrimitive
from CryptoPrimitives.OWF import OWF
from CryptoPrimitives.PRG import PRG
from CryptoPrimitives.MAC import MAC
from CryptoPrimitives.PRF import PRF
from collections import deque

# Import your pure logic functions from the Implementations folder
from Implementations.PA_1 import convert_owf_to_prg
from Implementations.PA_2 import ggm_prf_logic
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

    def convert_owf_to_prg(self, owf_instance: OWF):
        """PA #1: HILL Construction"""
        return convert_owf_to_prg(owf_instance)

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
    def Encrypt(mode, k, M):
        """
        Unified encryption interface.
        """
        if mode == Primitive.CBC:
            # For CBC, Enc returns IV and Ciphertext.
            return CBC_Enc(k, M)
        elif mode == Primitive.OFB:
            # For OFB, you need an IV. Let's assume it's generated here or passed in.
            # The spec says OFB_Enc(k, IV, M), so we should probably take it as an argument.
            # This interface might need adjustment based on your final function signatures.
            # For now, let's assume PA_4.py handles IV generation.
            iv, ciphertext = OFB_Enc_Dec(k, None, M) # Placeholder for IV handling
            return iv, ciphertext
        elif mode == Primitive.CTR:
            # For CTR, Enc returns nonce and Ciphertext.
            return CTR_Enc(k, M)
        else:
            raise NotImplementedError(f"Encryption for {mode.name} is not implemented.")

    def Decrypt(mode, k, C_bundle):
        """
        Unified decryption interface.
        C_bundle is expected to contain the ciphertext and any other needed values like IV or nonce.
        """
        if mode == Primitive.CBC:
            IV, C = C_bundle
            return CBC_Dec(k, IV, C)
        elif mode == Primitive.OFB:
            IV, C = C_bundle
            return OFB_Enc_Dec(k, IV, C) # Same function for encryption and decryption
        elif mode == Primitive.CTR:
            nonce, C = C_bundle
            return CTR_Dec(k, nonce, C)
        else:
            raise NotImplementedError(f"Decryption for {mode.name} is not implemented.")    