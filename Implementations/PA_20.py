# Implementations/PA_20.py

from PA_19 import Secure_AND, Secure_XOR, Secure_NOT

# =====================================================================
# 1. BOOLEAN CIRCUIT EVALUATOR
# =====================================================================

class Circuit:
    """Represents a boolean function as a DAG of gates[cite: 1435, 1436]."""
    def __init__(self, n_bits: int):
        self.n_bits = n_bits
        self.gates = []
        self.wire_count = 0
        
        # Allocate input wires for Alice (x) and Bob (y)
        self.alice_wires = [self._next_wire() for _ in range(n_bits)]
        self.bob_wires = [self._next_wire() for _ in range(n_bits)]
        self.output_wires = []

    def _next_wire(self) -> int:
        w = self.wire_count
        self.wire_count += 1
        return w

    def add_gate(self, gate_type: str, in1: int, in2: int = None) -> int:
        out_wire = self._next_wire()
        self.gates.append((gate_type, in1, in2, out_wire))
        return out_wire

    def set_outputs(self, out_wires: list[int]):
        self.output_wires = out_wires

    # --- Syntactic Sugar for Circuit Building ---
    def AND(self, w1: int, w2: int) -> int:
        return self.add_gate('AND', w1, w2)

    def XOR(self, w1: int, w2: int) -> int:
        return self.add_gate('XOR', w1, w2)

    def NOT(self, w1: int) -> int:
        return self.add_gate('NOT', w1)

    def OR(self, w1: int, w2: int) -> int:
        # A v B = ~(~A ^ ~B)
        not1 = self.NOT(w1)
        not2 = self.NOT(w2)
        and_gate = self.AND(not1, not2)
        return self.NOT(and_gate)


def Secure_Eval(circuit: Circuit, x_Alice: int, y_Bob: int) -> int:
    """
    Evaluates the circuit securely using only PA#19 primitives[cite: 1437].
    Traverses the circuit in topological order[cite: 1438].
    """
    # Initialize wire states
    wires = [0] * circuit.wire_count
    
    # Load inputs (extracting bits from LSB to MSB)
    for i in range(circuit.n_bits):
        wires[circuit.alice_wires[i]] = (x_Alice >> i) & 1
        wires[circuit.bob_wires[i]] = (y_Bob >> i) & 1

    # Evaluate gates in topological order
    for gate_type, in1, in2, out_wire in circuit.gates:
        if gate_type == 'AND':
            wires[out_wire] = Secure_AND(wires[in1], wires[in2])
        elif gate_type == 'XOR':
            wires[out_wire] = Secure_XOR(wires[in1], wires[in2])
        elif gate_type == 'NOT':
            wires[out_wire] = Secure_NOT(wires[in1])
        else:
            raise ValueError(f"Unknown gate type: {gate_type}")

    # Collect output bits and pack into integer
    result = 0
    for i, out_w in enumerate(circuit.output_wires):
        result |= (wires[out_w] << i)
        
    return result

# =====================================================================
# 2. MANDATORY TEST CIRCUITS
# =====================================================================

def build_equality_circuit(n: int) -> Circuit:
    """Circuit for x == y[cite: 1443]."""
    c = Circuit(n)
    eq_bits = []
    
    for i in range(n):
        # x_i XNOR y_i  <=>  NOT(x_i XOR y_i)
        xor_w = c.XOR(c.alice_wires[i], c.bob_wires[i])
        xnor_w = c.NOT(xor_w)
        eq_bits.append(xnor_w)
        
    # AND all equality bits together
    current = eq_bits[0]
    for i in range(1, n):
        current = c.AND(current, eq_bits[i])
        
    c.set_outputs([current])
    return c

def build_millionaire_circuit(n: int) -> Circuit:
    """Circuit for x > y (Millionaire's Problem)[cite: 1440, 1441]."""
    c = Circuit(n)
    
    gt_prev = None
    
    # Iterate from LSB to MSB
    # A standard iterative comparator: x > y is true if x_i > y_i at the most significant 
    # differing bit.
    for i in range(n):
        x_i = c.alice_wires[i]
        y_i = c.bob_wires[i]
        
        # g_i = x_i AND (NOT y_i)  --> x_i > y_i for this bit
        not_y = c.NOT(y_i)
        g_i = c.AND(x_i, not_y)
        
        # e_i = NOT(x_i XOR y_i)   --> x_i == y_i for this bit
        xor_w = c.XOR(x_i, y_i)
        e_i = c.NOT(xor_w)
        
        if gt_prev is None:
            gt_prev = g_i
        else:
            # gt_current = g_i OR (e_i AND gt_prev)
            e_and_gt = c.AND(e_i, gt_prev)
            gt_prev = c.OR(g_i, e_and_gt)
            
    c.set_outputs([gt_prev])
    return c

def build_adder_circuit(n: int) -> Circuit:
    """Circuit for x + y mod 2^n[cite: 1444]."""
    c = Circuit(n)
    
    carry = None
    sum_wires = []
    
    for i in range(n):
        x_i = c.alice_wires[i]
        y_i = c.bob_wires[i]
        
        # Half Adder logic for the first bit, Full Adder for the rest
        xor_xy = c.XOR(x_i, y_i)
        
        if carry is None:
            sum_wires.append(xor_xy)
            carry = c.AND(x_i, y_i)
        else:
            # sum_i = x_i XOR y_i XOR carry
            sum_i = c.XOR(xor_xy, carry)
            sum_wires.append(sum_i)
            
            # carry_next = (x_i AND y_i) XOR (carry AND (x_i XOR y_i))
            # (XOR is safe to use as OR here because the two conditions are mutually exclusive)
            and_xy = c.AND(x_i, y_i)
            and_carry_xor = c.AND(carry, xor_xy)
            carry = c.XOR(and_xy, and_carry_xor)
            
    c.set_outputs(sum_wires)
    return c

# =====================================================================
# 3. TESTS
# =====================================================================

def test_circuits():
    print("\n--- Running MPC Circuit Tests (n=4 bits) ---")
    n = 4
    
    circ_eq = build_equality_circuit(n)
    circ_gt = build_millionaire_circuit(n)
    circ_add = build_adder_circuit(n)
    
    passed = True
    for x in range(1 << n):
        for y in range(1 << n):
            
            # 1. Equality Test
            expected_eq = 1 if x == y else 0
            actual_eq = Secure_Eval(circ_eq, x, y)
            if actual_eq != expected_eq:
                print(f"Eq failed for x={x}, y={y}. Got {actual_eq}")
                passed = False
                
            # 2. Millionaire's Test
            expected_gt = 1 if x > y else 0
            actual_gt = Secure_Eval(circ_gt, x, y)
            if actual_gt != expected_gt:
                print(f"Gt failed for x={x}, y={y}. Got {actual_gt}")
                passed = False
                
            # 3. Adder Test (mod 2^n)
            expected_add = (x + y) % (1 << n)
            actual_add = Secure_Eval(circ_add, x, y)
            if actual_add != expected_add:
                print(f"Add failed for x={x}, y={y}. Expected {expected_add}, Got {actual_add}")
                passed = False
                
    if passed:
        print("[+] All circuit logic tests passed successfully for all input combinations! [cite: 1388]")
    else:
        print("[-] Some tests failed.")

if __name__ == "__main__":
    test_circuits()